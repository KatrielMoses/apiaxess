// Pure scope-rule model for the GUI: parse what the operator named into a
// port-specific allow rule, check coverage against existing rules, and label
// rules the way the engine does (`AllowedNetworkTarget::label`). No DOM, so
// scripts/check-scope-model.mjs can exercise it under Node.

export interface ScopeTarget { readonly label: string; readonly kind: "exact" | "domain_suffix"; readonly value: string; readonly ports: readonly number[] }

/** Ports a rule gets when the operator named a host without one: the web's two
 *  defaults, never "any port", so nothing is authorized beyond what they meant. */
export const DEFAULT_SCOPE_PORTS: readonly number[] = [80, 443];

/** The scope target for an origin the operator named — a URL, `host:port`,
 *  `[v6]:port`, a bare host, or `*.domain` for a domain and its subdomains.
 *  Always port-specific: the URL's (or scheme's default) port, the typed port,
 *  or 80 and 443 for a bare host. Returns `null` when there is no usable host
 *  or the port is invalid. The `label` reads exactly as the rule will
 *  ("127.0.0.1:9201", "api.example.com (ports 80, 443)"). */
export function scopeTargetFor(input: string): ScopeTarget | null {
  let text = input.trim();
  const suffix = text.startsWith("*.");
  if (suffix) text = text.slice(2);
  let host = "";
  let port: number | null = null;
  if (text.includes("://")) {
    try {
      const url = new URL(text);
      host = url.hostname;
      const scheme = url.protocol.replace(/:$/, "").toLowerCase();
      port = url.port !== "" ? Number(url.port) : (scheme === "http" || scheme === "ws" ? 80 : scheme === "https" || scheme === "wss" ? 443 : null);
    } catch {
      return null;
    }
  } else {
    const authority = text.split(/[/?#]/)[0] ?? "";
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
    const hostPort = /^([^:]+):(\d+)$/.exec(authority);
    const colons = (authority.match(/:/g) ?? []).length;
    if (bracketed !== null) { host = bracketed[1] ?? ""; port = bracketed[2] === undefined ? null : Number(bracketed[2]); }
    else if (hostPort !== null) { host = hostPort[1] ?? ""; port = Number(hostPort[2]); }
    else if (colons === 1) return null; // "host:" or "host:abc"
    else host = authority; // a bare host, or an unbracketed IPv6 literal
  }
  host = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (host === "" || /[\s/]/.test(host)) return null;
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) return null;
  if (suffix && (host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host))) return null;
  const ports = port === null ? [...DEFAULT_SCOPE_PORTS] : [port];
  const kind = suffix ? "domain_suffix" : "exact";
  const rule: ScopeRule = { id: "", host: kind === "exact" ? { kind, host } : { kind, domain: host }, ports };
  return { label: scopeRuleDisplay(rule), kind, value: host, ports };
}

/** True when `rule` already authorizes `target`'s host on `port` (mirrors the
 *  engine's `AllowedNetworkTarget::matches`). A domain-suffix target is covered
 *  only by a suffix rule at or above its domain. */
export function scopeRuleCovers(rule: ScopeRule, target: ScopeTarget, port: number): boolean {
  const under = (domain: string): boolean => target.value === domain || target.value.endsWith(`.${domain}`);
  const hostCovered = rule.host.kind === "exact"
    ? target.kind === "exact" && rule.host.host === target.value
    : under(rule.host.domain ?? "");
  return hostCovered && (rule.ports.length === 0 || rule.ports.includes(port));
}

export interface ScopeRule { id: string; host: { kind: string; domain?: string; host?: string }; ports: number[] }

/** The label a scope rule is shown with: its exact host or its domain. */
export function scopeRuleLabel(rule: ScopeRule): string {
  return rule.host.kind === "exact" ? (rule.host.host ?? "") : (rule.host.domain ?? "");
}

/** A scope rule as the operator must read it: with its port restriction, so a
 *  host is never mistaken as authorized on every port (mirrors the engine's
 *  `AllowedNetworkTarget::label`). */
export function scopeRuleDisplay(rule: ScopeRule): string {
  const raw = scopeRuleLabel(rule);
  const host = rule.host.kind === "exact" ? (raw.includes(":") ? `[${raw}]` : raw) : `*.${raw}`;
  if (rule.ports.length === 0) return `${host} (any port)`;
  if (rule.ports.length === 1) return `${host}:${rule.ports[0]}`;
  return `${host} (ports ${rule.ports.join(", ")})`;
}
