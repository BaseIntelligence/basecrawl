"""Authoritative validation of retained BuildKit provenance records.

Both durable measurement reconciliation and reproducibility checks call this
module.  A BuildKit output is accepted only when its canonical reference
resolves to the retained immutable history, its invocation and materials
match exactly, and its output attachment is bound to the expected digest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


SOURCE_DATE_EPOCH = "1700000000"
EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_DESCRIPTOR_PLATFORM = {"architecture": "amd64", "os": "linux"}
EXPECTED_FRONTEND = "gateway.v0"
EXPECTED_SOURCE = (
    "docker/dockerfile:1.7@"
    "sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
)
EXPECTED_CMDLINE = EXPECTED_SOURCE
EXPECTED_CONFIG_ENTRY_POINT = "Dockerfile"
EXPECTED_BUILD_NAME = "basecrawl/image"
EXPECTED_CONTEXT = "basecrawl"
EXPECTED_DOCKERFILE = "image/Dockerfile"
_REFERENCE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_-]{8,}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALGORITHM = re.compile(r"^[A-Za-z][A-Za-z0-9+._-]*$")
_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_OUTPUT_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)


class BuildKitProvenanceError(ValueError):
    """A BuildKit record is malformed, unresolved, or internally inconsistent."""

    def __init__(self, message: str, *, code: str = "invalid_buildkit_provenance"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BuildKitRecord:
    """The normalized identity returned by the authoritative validator."""

    digest: str
    canonical_ref: str
    materials: frozenset[tuple[str, str, str]]


def _fail(message: str, *, code: str = "invalid_buildkit_provenance") -> None:
    raise BuildKitProvenanceError(message, code=code)


def canonical_reference(value: Any, *, index: int) -> str:
    """Validate and return a canonical full BuildKit history reference."""

    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        _fail(
            f"BuildKit metadata[{index}] has an unverifiable build reference: {value!r}",
            code="invalid_buildkit_reference",
        )
    return value


def _normalize_uri(value: Any, *, index: int, source: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(character.isspace() for character in value)
    ):
        _fail(
            f"BuildKit history[{index}] {source} material URI is malformed",
            code="unverifiable_buildkit_reference",
        )
    parts = value.split("&")
    retained = [part for part in parts if not part.lower().startswith("platform=")]
    normalized = "&".join(retained)
    if not normalized:
        _fail(
            f"BuildKit history[{index}] {source} material URI is empty",
            code="unverifiable_buildkit_reference",
        )
    return normalized


def _normalize_digest(
    algorithm: Any,
    value: Any,
    *,
    index: int,
    source: str,
) -> tuple[str, str]:
    if not isinstance(algorithm, str) or _ALGORITHM.fullmatch(algorithm) is None:
        _fail(
            f"BuildKit history[{index}] {source} material digest algorithm is malformed",
            code="unverifiable_buildkit_reference",
        )
    if not isinstance(value, str):
        _fail(
            f"BuildKit history[{index}] {source} material digest is malformed",
            code="unverifiable_buildkit_reference",
        )
    algorithm = algorithm.lower()
    if algorithm != "sha256":
        _fail(
            f"BuildKit history[{index}] {source} material digest algorithm is unsupported",
            code="unverifiable_buildkit_reference",
        )
    value_algorithm, separator, digest = value.partition(":")
    if separator:
        if value_algorithm.lower() != algorithm:
            _fail(
                f"BuildKit history[{index}] {source} material digest algorithm mismatch",
                code="buildkit_material_mismatch",
            )
    else:
        digest = value
    if _HEX.fullmatch(digest) is None:
        _fail(
            f"BuildKit history[{index}] {source} material digest is malformed",
            code="unverifiable_buildkit_reference",
        )
    return algorithm, digest.lower()


def _metadata_materials(
    materials: Any,
    *,
    index: int,
) -> frozenset[tuple[str, str, str]]:
    if not isinstance(materials, list) or not materials:
        _fail(
            f"BuildKit history[{index}] metadata has no verifiable materials",
            code="unverifiable_buildkit_reference",
        )
    normalized: set[tuple[str, str, str]] = set()
    for material in materials:
        if (
            not isinstance(material, Mapping)
            or "uri" not in material
            or not isinstance(material.get("digest"), Mapping)
            or not material["digest"]
        ):
            _fail(
                f"BuildKit history[{index}] metadata materials are malformed",
                code="unverifiable_buildkit_reference",
            )
        uri = _normalize_uri(material["uri"], index=index, source="metadata")
        for algorithm, digest in material["digest"].items():
            normalized.add(
                (
                    uri,
                    *_normalize_digest(
                        algorithm,
                        digest,
                        index=index,
                        source="metadata",
                    ),
                )
            )
    return frozenset(normalized)


def _history_materials(
    materials: Any,
    *,
    index: int,
) -> frozenset[tuple[str, str, str]]:
    if not isinstance(materials, list) or not materials:
        _fail(
            f"BuildKit history[{index}] has no verifiable materials",
            code="unverifiable_buildkit_reference",
        )
    normalized: set[tuple[str, str, str]] = set()
    for material in materials:
        if (
            not isinstance(material, Mapping)
            or not isinstance(material.get("URI"), str)
            or not isinstance(material.get("Digests"), list)
            or not material["Digests"]
        ):
            _fail(
                f"BuildKit history[{index}] materials are malformed",
                code="unverifiable_buildkit_reference",
            )
        uri = _normalize_uri(material["URI"], index=index, source="history")
        for digest_value in material["Digests"]:
            if not isinstance(digest_value, str):
                _fail(
                    f"BuildKit history[{index}] material digest is malformed",
                    code="unverifiable_buildkit_reference",
                )
            algorithm = digest_value.partition(":")[0]
            normalized.add(
                (
                    uri,
                    *_normalize_digest(
                        algorithm,
                        digest_value,
                        index=index,
                        source="history",
                    ),
                )
            )
    return frozenset(normalized)


def _invocation_identity(
    invocation: Mapping[str, Any],
    *,
    index: int,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """Normalize the complete BuildKit source/invocation identity.

    The provenance schema has several nested maps whose unknown keys can
    silently change what was built.  Keep the accepted surface deliberately
    exact, then bind each value to the immutable history identity below.
    """

    config_source = invocation.get("configSource")
    parameters = invocation.get("parameters")
    environment = invocation.get("environment")
    if (
        set(invocation) != {"configSource", "parameters", "environment"}
        or not isinstance(config_source, Mapping)
        or set(config_source) != {"entryPoint"}
        or config_source.get("entryPoint") != EXPECTED_CONFIG_ENTRY_POINT
        or not isinstance(parameters, Mapping)
        or set(parameters) != {"frontend", "args", "locals"}
        or parameters.get("frontend") != EXPECTED_FRONTEND
        or not isinstance(environment, Mapping)
        or set(environment) != {"platform"}
        or environment.get("platform") != EXPECTED_PLATFORM
    ):
        _fail(
            f"BuildKit metadata[{index}] invocation identity is not canonical",
            code="buildkit_invocation_mismatch",
        )
    args = parameters["args"]
    locals_ = parameters["locals"]
    if (
        not isinstance(args, Mapping)
        or set(args)
        != {
            "build-arg:SOURCE_DATE_EPOCH",
            "cmdline",
            "no-cache",
            "source",
        }
        or args.get("build-arg:SOURCE_DATE_EPOCH") != SOURCE_DATE_EPOCH
        or args.get("cmdline") != EXPECTED_CMDLINE
        or args.get("no-cache") != ""
        or args.get("source") != EXPECTED_SOURCE
        or not isinstance(locals_, list)
        or len(locals_) != 2
        or any(
            not isinstance(local, Mapping) or set(local) != {"name"}
            for local in locals_
        )
        or [local["name"] for local in locals_] != ["context", "dockerfile"]
    ):
        _fail(
            f"BuildKit metadata[{index}] source identity is not canonical",
            code="buildkit_invocation_mismatch",
        )
    return config_source, parameters, environment


def _descriptor_platform(
    descriptor: Mapping[str, Any],
    *,
    index: int,
) -> Mapping[str, str]:
    platform = descriptor.get("platform")
    if (
        not isinstance(platform, Mapping)
        or set(platform) != set(EXPECTED_DESCRIPTOR_PLATFORM)
        or platform != EXPECTED_DESCRIPTOR_PLATFORM
    ):
        _fail(
            f"BuildKit metadata[{index}] output descriptor platform is not canonical",
            code="buildkit_output_mismatch",
        )
    return platform


def _manifest_key(path: Path) -> str:
    path_text = path.as_posix()
    marker = "/evidence/m2/"
    if marker in path_text:
        return path_text.split(marker, 1)[1]
    if path_text.startswith("evidence/m2/"):
        return path_text.removeprefix("evidence/m2/")
    return path.name


def _validate_manifest_binding(
    path: Path,
    *,
    manifest_files: Mapping[str, str],
    label: str,
    index: int,
) -> None:
    key = _manifest_key(path)
    expected = manifest_files.get(key)
    if not isinstance(expected, str):
        _fail(
            f"BuildKit {label}[{index}] is not covered by the evidence manifest: {key}",
            code="unmanifested_buildkit_reference",
        )
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        _fail(
            f"BuildKit {label}[{index}] cannot be read: {error}",
            code="unresolved_buildkit_reference",
        )
    if actual != expected:
        _fail(
            f"BuildKit {label}[{index}] does not match its evidence manifest",
            code="unmanifested_buildkit_reference",
        )


def _validate_history(
    metadata: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    digest: str,
    canonical_ref: str,
    invocation: Mapping[str, Any],
    metadata_materials: frozenset[tuple[str, str, str]],
    index: int,
) -> frozenset[tuple[str, str, str]]:
    reference_id = canonical_ref.rsplit("/", 1)[-1]
    if (
        history.get("Ref") not in {canonical_ref, reference_id}
        or history.get("Name") != EXPECTED_BUILD_NAME
        or history.get("Context") != EXPECTED_CONTEXT
        or history.get("Dockerfile") != EXPECTED_DOCKERFILE
        or history.get("Status") != "completed"
        or not isinstance(history.get("VCSRevision"), str)
        or not history["VCSRevision"].strip()
    ):
        _fail(
            f"BuildKit history[{index}] reference is not bound to metadata",
            code="buildkit_reference_mismatch",
        )
    environment = invocation["environment"]
    config_source = invocation["configSource"]
    parameters = invocation["parameters"]
    args = parameters["args"]
    if (
        parameters["frontend"] != EXPECTED_FRONTEND
        or args["source"] != EXPECTED_SOURCE
        or args["cmdline"] != EXPECTED_CMDLINE
        or config_source["entryPoint"] != EXPECTED_DOCKERFILE.rsplit("/", 1)[-1]
        or history["Dockerfile"] != EXPECTED_DOCKERFILE
        or history["Context"] != EXPECTED_CONTEXT
    ):
        _fail(
            f"BuildKit history[{index}] source and invocation identity does not match metadata",
            code="buildkit_invocation_mismatch",
        )
    if not isinstance(history.get("Platform"), list) or history["Platform"] != [
        environment["platform"]
    ]:
        _fail(
            f"BuildKit history[{index}] invocation platform does not match metadata",
            code="buildkit_invocation_mismatch",
        )
    build_args = history.get("BuildArgs")
    config = history.get("Config")
    if (
        not isinstance(build_args, list)
        or len(build_args) != 1
        or not isinstance(build_args[0], Mapping)
        or set(build_args[0]) != {"Name", "Value"}
        or build_args[0].get("Name") != "SOURCE_DATE_EPOCH"
        or build_args[0].get("Value") != SOURCE_DATE_EPOCH
        or not isinstance(config, Mapping)
        or set(config) != {"ImageResolveMode", "NoCache", "SourceDateEpoch"}
        or config.get("ImageResolveMode") != "local"
        or config.get("NoCache") is not True
        or config.get("SourceDateEpoch") != SOURCE_DATE_EPOCH
    ):
        _fail(
            f"BuildKit history[{index}] invocation configuration does not match metadata",
            code="buildkit_invocation_mismatch",
        )
    history_materials = _history_materials(
        history.get("Materials"),
        index=index,
    )
    if metadata_materials != history_materials:
        _fail(
            f"BuildKit history[{index}] materials do not exactly match metadata",
            code="buildkit_material_mismatch",
        )
    attachments = history.get("Attachments")
    if not isinstance(attachments, list) or not any(
        isinstance(attachment, Mapping)
        and attachment.get("Digest") == digest
        and attachment.get("Type") in _OUTPUT_TYPES
        for attachment in attachments
    ):
        _fail(
            f"BuildKit history[{index}] output identity does not match metadata",
            code="buildkit_output_mismatch",
        )
    return history_materials


def validate_buildkit_record(
    metadata: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    expected_digest: str,
    index: int,
    metadata_path: Path | None = None,
    history_path: Path | None = None,
    manifest_files: Mapping[str, str] | None = None,
) -> BuildKitRecord:
    """Validate one metadata/history pair and return normalized immutable identity."""

    if not isinstance(metadata, Mapping) or not isinstance(history, Mapping):
        _fail(f"BuildKit record[{index}] must contain metadata and history objects")
    if (
        not isinstance(expected_digest, str)
        or _DIGEST.fullmatch(expected_digest) is None
    ):
        _fail(f"BuildKit expected digest[{index}] is malformed")
    if (metadata_path is None) != (history_path is None) or (
        metadata_path is not None and manifest_files is None
    ):
        _fail(
            f"BuildKit record[{index}] manifest coverage is incomplete",
            code="unmanifested_buildkit_reference",
        )
    if metadata_path is not None and history_path is not None:
        _validate_manifest_binding(
            metadata_path,
            manifest_files=manifest_files or {},
            label="metadata",
            index=index,
        )
        _validate_manifest_binding(
            history_path,
            manifest_files=manifest_files or {},
            label="history",
            index=index,
        )

    digest = metadata.get("containerimage.digest")
    if (
        not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or digest != expected_digest
    ):
        _fail(
            f"BuildKit metadata[{index}] has an invalid or unexpected output digest: {digest!r}"
        )
    canonical_ref = canonical_reference(
        metadata.get("buildx.build.ref"),
        index=index,
    )
    provenance = metadata.get("buildx.build.provenance")
    if not isinstance(provenance, Mapping):
        _fail(f"BuildKit metadata[{index}] has no provenance invocation")
    invocation = provenance.get("invocation")
    if not isinstance(invocation, Mapping):
        _fail(f"BuildKit metadata[{index}] has no provenance invocation")
    _, parameters, environment = _invocation_identity(invocation, index=index)
    descriptor = metadata.get("containerimage.descriptor")
    if (
        not isinstance(descriptor, Mapping)
        or descriptor.get("digest") != digest
        or descriptor.get("mediaType") not in _OUTPUT_TYPES
        or not isinstance(descriptor.get("size"), int)
        or descriptor["size"] <= 0
    ):
        _fail(
            f"BuildKit metadata[{index}] output descriptor is not bound to the digest",
            code="buildkit_output_mismatch",
        )
    descriptor_platform = _descriptor_platform(descriptor, index=index)
    if descriptor_platform != {
        "architecture": environment["platform"].split("/", 1)[1],
        "os": environment["platform"].split("/", 1)[0],
    } or history.get("Platform") != [environment["platform"]]:
        _fail(
            f"BuildKit metadata[{index}] output platform is not bound to invocation history",
            code="buildkit_output_mismatch",
        )
    materials = _metadata_materials(provenance.get("materials"), index=index)
    _validate_history(
        metadata,
        history,
        digest=digest,
        canonical_ref=canonical_ref,
        invocation=invocation,
        metadata_materials=materials,
        index=index,
    )
    return BuildKitRecord(
        digest=digest,
        canonical_ref=canonical_ref,
        materials=materials,
    )


def validate_independent_records(
    records: Sequence[BuildKitRecord],
    *,
    expected_count: int = 2,
) -> None:
    """Require independent canonical BuildKit references, regardless of digest."""

    if len(records) < expected_count:
        _fail(
            f"at least {expected_count} independent BuildKit records are required",
            code="insufficient_buildkit_records",
        )
    references = [record.canonical_ref for record in records]
    if len(set(references)) != len(references):
        _fail(
            f"BuildKit build references are not distinct: {references!r}",
            code="reused_buildkit_reference",
        )
