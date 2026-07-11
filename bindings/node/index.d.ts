export interface ScrapeOptions {
  formats?: string[];
  taskId?: string;
  task_id?: string;
  nonce?: string;
  timeoutSecs?: number;
  timeout_secs?: number;
  headers?: [string, string][];
  insecure?: boolean;
  maxBodyBytes?: number;
  max_body_bytes?: number;
  crawlDelayMs?: number;
  crawl_delay_ms?: number;
  viewport?: [number, number];
  screenshotFullPage?: boolean;
  screenshot_full_page?: boolean;
  renderEnabled?: boolean;
  render_enabled?: boolean;
  waitFor?: string;
  wait_for?: string;
  renderTimeoutSecs?: number;
  render_timeout_secs?: number;
  followPagination?: boolean;
  follow_pagination?: boolean;
  maxPages?: number;
  max_pages?: number;
  robotsPolicy?: "enforce" | "observe" | "ignore";
  robots_policy?: "enforce" | "observe" | "ignore";
  attest?: boolean;
}

export interface ScrapeProof {
  version: number;
  task_id?: string;
  nonce?: string;
  request: Record<string, unknown>;
  tls: Record<string, unknown>;
  response: Record<string, unknown>;
  result: Record<string, unknown>;
  egress: Record<string, unknown>;
  attestation: Record<string, unknown>;
  sdk_signature: Record<string, unknown>;
}

export function scrape(url: string, options?: ScrapeOptions): ScrapeProof;
export function version(): string;
