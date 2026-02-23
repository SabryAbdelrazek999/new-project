import axios from "axios";

interface ZapAlert {
  id: string;
  pluginId: string;
  pluginName?: string;
  alert?: string; // Often ZAP uses 'alert' for the name
  name?: string;
  description: string;
  solution: string;
  riskCode?: string;
  riskcode?: string; // Some versions use lowercase
  risk?: string; // String representation (High, Medium, etc)
  confidence: string;
  riskdesc?: string;
  confidencedesc?: string;
  url: string;
  messageId?: string;
  evidence?: string;
  param?: string;
}

interface ZapScanResult {
  alerts: ZapAlert[];
  vulnerabilities: Array<{
    type: string;
    severity: "critical" | "high" | "medium" | "low";
    title: string;
    description: string;
    affectedUrl: string;
    remediation: string;
    details: Record<string, any>;
  }>;
}

/**
 * ZAP client for communicating with OWASP ZAP daemon.
 * Uses ZAP_API_URL environment variable (default: http://localhost:8080)
 */
export class ZapClient {
  private baseUrl: string;
  private client = axios.create({
    headers: {
      'User-Agent': 'ZAP-Scanner-Client',
      'Connection': 'keep-alive'
    }
  });
  private activeScanIds: Set<string> = new Set();

  constructor(baseUrl?: string) {
    // Use environment variable with fallback
    // When running on host machine, use localhost:8081 (docker-compose port mapping)
    // In Docker container, would use: zap service name
    this.baseUrl = baseUrl || process.env.ZAP_API_URL || "http://localhost:8081";
    console.log(`[ZAP] Initialized client with base URL: ${this.baseUrl}`);
  }

  /**
   * Check if ZAP daemon is ready with exponential backoff retry
   */
  async isReady(maxAttempts = 30, initialDelay = 2000): Promise<boolean> {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        console.log(`[ZAP] Checking daemon readiness (attempt ${i + 1}/${maxAttempts})...`);
        const response = await this.client.get(`${this.baseUrl}`, {
          timeout: 10000,
        });
        if (response.status === 200) {
          console.log('[ZAP] ✅ Daemon is ready!');
          return true;
        }
      } catch (error: any) {
        const delay = initialDelay * Math.pow(1.5, i); // Exponential backoff
        console.log(`[ZAP] ⏳ Attempt ${i + 1} failed: ${error.message}. Retrying in ${Math.round(delay / 1000)}s...`);

        if (i < maxAttempts - 1) {
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    console.error('[ZAP] ❌ Daemon failed to start within timeout');
    return false;
  }

  /**
   * Create a new session to clear ZAP's internal database
   * This prevents the "Data cache size limit is reached" error
   */
  async clearSession(): Promise<void> {
    try {
      console.log('[ZAP] Creating new session to clear database...');
      await this.client.get(
        `${this.baseUrl}/JSON/core/action/newSession?overwrite=true`,
        { timeout: 60000 } // Increased to 60s
      );
      console.log('[ZAP] ✅ New session created, database cleared');
    } catch (error: any) {
      console.log(`[ZAP] ⚠️  Could not create new session: ${error.message}`);
      // Non-fatal, continue anyway
    }
  }

  /**
   * Stop an active scan
   */
  async stopScan(scanId: string): Promise<void> {
    try {
      console.log(`[ZAP] Stopping active scan ${scanId}...`);
      await this.client.get(
        `${this.baseUrl}/JSON/ascan/action/stop?scanId=${scanId}`,
        { timeout: 10000 }
      );
      this.activeScanIds.delete(scanId);
      console.log(`[ZAP] ✅ Scan ${scanId} stopped`);
    } catch (error: any) {
      console.error(`[ZAP] Failed to stop scan ${scanId}:`, error.message);
    }
  }

  /**
   * Stop all active scans
   */
  async stopAllScans(): Promise<void> {
    try {
      console.log('[ZAP] Stopping all active scans...');
      await this.client.get(
        `${this.baseUrl}/JSON/ascan/action/stopAllScans`,
        { timeout: 10000 }
      );
      this.activeScanIds.clear();
      console.log('[ZAP] ✅ All scans stopped');
    } catch (error: any) {
      console.error('[ZAP] Failed to stop all scans:', error.message);
    }
  }

  /**
   * Start an active scan on the target URL
   * Returns scan ID
   */
  async startScan(targetUrl: string, scanDepth: string = "medium"): Promise<string> {
    try {
      console.log(`[ZAP] Starting active scan for ${targetUrl} (depth: ${scanDepth})`);

      // First, add URL to context
      const encodedUrl = encodeURIComponent(targetUrl);

      // Step 1: Access the URL first (important!)
      try {
        await this.client.get(
          `${this.baseUrl}/JSON/core/action/accessUrl?url=${encodedUrl}`,
          { timeout: 60000 }
        );
        console.log(`[ZAP] ✅ URL accessed: ${targetUrl}`);
      } catch (err) {
        console.log(`[ZAP] ⚠️  Could not access URL directly, continuing...`);
      }

      // Step 2: Spider the target (configure based on depth)
      try {
        let maxChildren: number;
        let maxDepth: number;
        let maxDuration: number;

        if (scanDepth === "shallow") {
          maxChildren = 10;  // 10 children per page for better coverage
          maxDepth = 3;      // 3 levels deep
          maxDuration = 5;   // 5 minutes max (increased for flexibility)
        } else if (scanDepth === "deep") {
          maxChildren = 0;   // 0 = unlimited children (thorough crawling)
          maxDepth = 0;      // 0 = unlimited depth
          maxDuration = 30;  // 30 minutes max (reasonable for deep scans)
        } else {
          maxChildren = 10;  // 10 children per page
          maxDepth = 5;      // 5 levels deep
          maxDuration = 20;  // 20 minutes max (increased for flexibility)
        }

        const spiderResponse = await this.client.get(
          `${this.baseUrl}/JSON/spider/action/scan?url=${encodedUrl}&maxChildren=${maxChildren}&maxDepth=${maxDepth}&maxDuration=${maxDuration}&recurse=true&subtreeOnly=${scanDepth === "shallow" ? "true" : "false"}`,
          { timeout: 60000 }
        );
        const spiderScanId = spiderResponse.data.scan;
        console.log(`[ZAP] Spider started with ID: ${spiderScanId} (maxChildren: ${maxChildren}, maxDepth: ${maxDepth}, maxDuration: ${maxDuration}min)`);

        // Wait for spider to complete. Use flexible timeouts for different site sizes
        // to keep quick scans fast while allowing deeper scans more time.
        let spiderTimeoutMs = 300000; // default 5 mins
        if (scanDepth === "shallow") spiderTimeoutMs = 60000;     // 1 min
        if (scanDepth === "medium") spiderTimeoutMs = 600000;    // 10 mins (increased from 5)
        if (scanDepth === "deep") spiderTimeoutMs = 3600000;     // 60 mins

        await this.waitForSpider(spiderScanId, spiderTimeoutMs);
      } catch (err: any) {
        console.log(`[ZAP] ⚠️  Spider failed or timed out: ${err.message}, continuing with active scan...`);
      }

      // Step 3: Start active scan with policy and scan settings based on depth
      let scanUrl = `${this.baseUrl}/JSON/ascan/action/scan?url=${encodedUrl}&recurse=true&inScopeOnly=false`;

      // Configure scan settings based on depth
      if (scanDepth === "deep") {
        // For deep scans: aggressive settings
        console.log(`[ZAP] Configuring DEEP scan policy (aggressive)...`);
        scanUrl += `&policyName=Policy%20deep&enableAllScanners=true`;
      } else if (scanDepth === "medium") {
        // For medium scans: balanced settings
        console.log(`[ZAP] Configuring MEDIUM scan policy (balanced)...`);
        scanUrl += `&policyName=Policy%20standard`;
      } else {
        // For shallow scans: use standard policy for more coverage  
        console.log(`[ZAP] Configuring SHALLOW scan policy (standard for better coverage)...`);
        scanUrl += `&policyName=Policy%20standard`;
      }

      // Start the scan
      let response;
      try {
        response = await this.client.get(scanUrl, { timeout: 60000 });
        console.log(`[ZAP] ✅ Scan configured with depth-specific settings: ${scanDepth}`);
      } catch (policyError: any) {
        // If policy fails, try without it (uses default)
        console.log(`[ZAP] ⚠️  Policy configuration failed, using default policy...`);
        response = await this.client.get(
          `${this.baseUrl}/JSON/ascan/action/scan?url=${encodedUrl}&recurse=true&inScopeOnly=false`,
          { timeout: 60000 }
        );
      }

      const scanId = String(response.data.scan);
      this.activeScanIds.add(scanId);
      console.log(`[ZAP] ✅ Active scan started with ID: ${scanId}`);
      return scanId;
    } catch (error: any) {
      console.error("[ZAP] Failed to start scan:", error.message);
      if (error.response) {
        console.error("[ZAP] Response data:", error.response.data);
        console.error("[ZAP] Response status:", error.response.status);
      }
      throw new Error(`ZAP scan initiation failed: ${error.message}`);
    }
  }

  /**
   * Poll spider status until completion
   */
  async waitForSpider(scanId: string, maxWaitMs?: number): Promise<void> {
    const defaultTimeout = parseInt(process.env.ZAP_SPIDER_TIMEOUT_MS || "60000", 10); // 60s default (reduced from 900s) 
    const timeout = maxWaitMs || defaultTimeout;
    const startTime = Date.now();
    const pollInterval = 2000; // 2 seconds (increased from 5s for faster progress updates)

    while (Date.now() - startTime < timeout) {
      try {
        const response = await this.client.get(
          `${this.baseUrl}/JSON/spider/view/status?scanId=${scanId}`,
          { timeout: 30000 }
        );
        const progress = parseInt(response.data.status, 10);
        console.log(`[ZAP] Spider ${scanId} progress: ${progress}%`);

        if (progress === 100) {
          console.log(`[ZAP] ✅ Spider ${scanId} completed`);
          // Give it a moment to settle
          await new Promise(resolve => setTimeout(resolve, 2000));
          return;
        }

        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      } catch (error: any) {
        console.error(`[ZAP] Error polling spider status:`, error.message);
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(`ZAP spider ${scanId} did not complete within ${timeout}ms`);
  }

  /**
   * Poll scan status until completion
   * Progress is 0-100
   * Uses scanDepth to set appropriate timeouts
   */
  async waitForScan(scanId: string, maxWaitMs: number, onProgress?: (progress: number) => void, abortSignal?: AbortSignal, scanDepth?: string): Promise<void> {
    // Add extra buffer time to maxWaitMs for deep scans to complete fully
    let effectiveMaxWaitMs = maxWaitMs;
    if (scanDepth === "deep") {
      // For deep scans, add 50% buffer to the expected time
      effectiveMaxWaitMs = Math.ceil(maxWaitMs * 1.5);
      console.log(`[ZAP] ⏱️  Deep scan: effective timeout increased from ${maxWaitMs}ms to ${effectiveMaxWaitMs}ms`);
    }

    const startTime = Date.now();
    const pollInterval = 2000; // 2 seconds (increased from 5s for faster progress updates)
    let lastProgress = 0;
    let stuckCounter = 0; // Counter for stuck progress

    while (Date.now() - startTime < effectiveMaxWaitMs) {
      try {
        // Check if scan was aborted
        if (abortSignal?.aborted) {
          console.log(`[ZAP] Scan ${scanId} aborted by user, stopping ZAP scan...`);
          await this.stopScan(scanId);
          throw new Error("Scan cancelled by user");
        }

        const response = await this.client.get(
          `${this.baseUrl}/JSON/ascan/view/status?scanId=${scanId}`,
          { timeout: 30000 }
        );
        const progress = parseInt(response.data.status, 10);
        const elapsedSeconds = Math.round((Date.now() - startTime) / 1000);
        const elapsedMinutes = Math.round(elapsedSeconds / 60);

        console.log(`[ZAP] Scan ${scanId} progress: ${progress}% (elapsed: ${elapsedMinutes}m ${elapsedSeconds % 60}s)`);

        // Check if progress is stuck
        if (progress === lastProgress && progress < 100) {
          stuckCounter++;
          if (stuckCounter % 30 === 0) { // Every 60 seconds (30 * 2s)
            console.log(`[ZAP] ⚠️  Scan progress stuck at ${progress}% for ${stuckCounter * 2}s`);
          }
        } else {
          stuckCounter = 0; // Reset counter on progress change
        }

        lastProgress = progress;

        if (onProgress) {
          onProgress(progress);
        }

        if (progress === 100) {
          this.activeScanIds.delete(scanId);
          console.log(`[ZAP] ✅ Scan ${scanId} completed after ${elapsedMinutes}m`);
          return;
        }

        // Wait before polling again
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      } catch (error: any) {
        if (error.message === "Scan cancelled by user") {
          throw error;
        }
        console.error(`[ZAP] Error polling scan status:`, error.message);
        // Continue trying instead of throwing error immediately
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(`ZAP scan ${scanId} did not complete within ${Math.round(effectiveMaxWaitMs / 60000)} minutes (timeout: ${scanDepth || 'unknown'} scan)`);
  }

  /**
   * Retrieve all alerts for a scan
   * Note: scanId parameter may not work in all ZAP versions
   * We retrieve all alerts from the current session instead
   */
  async getAlerts(scanId?: string, filterUrl?: string): Promise<ZapAlert[]> {
    try {
      // Try with scanId first (for older ZAP versions)
      let response;
      if (scanId) {
        try {
          response = await this.client.get(
            `${this.baseUrl}/JSON/core/view/alerts?scanId=${scanId}`,
            { timeout: 30000 }
          );
        } catch (e) {
          console.log(`[ZAP] Warning: Failed to get alerts with scanId, falling back to all alerts...`);
          response = await this.client.get(
            `${this.baseUrl}/JSON/core/view/alerts`,
            { timeout: 30000 }
          );
        }
      } else {
        response = await this.client.get(
          `${this.baseUrl}/JSON/core/view/alerts`,
          { timeout: 30000 }
        );
      }

      let alerts: ZapAlert[] = response.data.alerts || [];
      console.log(`[ZAP] Retrieved ${alerts.length} alerts from scan${scanId ? ` ${scanId}` : ''}`);

      if (alerts.length > 0) {
        console.log(`[ZAP] Sample alert - Title: "${alerts[0].alert || alerts[0].name}", Risk: "${alerts[0].risk || alerts[0].riskCode || alerts[0].riskcode}"`);
      }

      // If caller provided a filterUrl, narrow alerts to those matching the target
      if (filterUrl) {
        try {
          const urlObj = new URL(filterUrl);
          const host = urlObj.hostname;
          alerts = alerts.filter(a => {
            try {
              if (!a.url) return false;
              const aUrl = new URL(a.url);
              return aUrl.hostname === host;
            } catch (e) {
              return String(a.url || '').includes(host);
            }
          });
          console.log(`[ZAP] Filtered alerts to ${alerts.length} items matching host ${host}`);
        } catch (e) {
          // ignore filtering errors
        }
      }

      return alerts;
    } catch (error: any) {
      console.error("[ZAP] Failed to get alerts:", error.message);
      return [];
    }
  }

  /**
   * Convert ZAP alerts to our vulnerability format
   */
  convertAlertsToVulnerabilities(alerts: ZapAlert[]): ZapScanResult["vulnerabilities"] {
    console.log(`[ZAP] Converting ${alerts.length} alerts to vulnerabilities`);
    if (alerts.length > 0) {
      console.log(`[ZAP] Debug - First alert keys: ${Object.keys(alerts[0]).join(", ")}`);
      const first = alerts[0];
      console.log(`[ZAP] Debug - First alert details:`);
      console.log(`  - Name: ${first.alert || first.name || first.pluginName}`);
      console.log(`  - RiskCode: ${first.riskCode}, riskcode: ${first.riskcode}, risk: ${first.risk}`);
      console.log(`  - URL: ${first.url}`);
    } else {
      console.log(`[ZAP] Warning: No alerts to convert - scan may not have found vulnerabilities or alerts were not retrieved`);
    }

    const riskMap: Record<string, "critical" | "high" | "medium" | "low"> = {
      "3": "critical",
      "High": "critical",
      "2": "high",
      "Medium": "high",
      "1": "medium",
      "Low": "medium",
      "0": "low",
      "Informational": "low",
    };

    return alerts.map((alert) => {
      // Find the best risk indicator
      const riskKey = alert.riskCode || alert.riskcode || alert.risk || "0";
      const severity = (riskMap[riskKey] || "low") as "critical" | "high" | "medium" | "low";
      const name = alert.alert || alert.name || alert.pluginName || "Unknown Vulnerability";

      return {
        type: alert.pluginName || name,
        severity,
        title: name,
        description: alert.description || "No description provided",
        affectedUrl: alert.url,
        remediation: alert.solution || "No solution provided",
        details: {
          pluginId: alert.pluginId,
          confidence: alert.confidencedesc || alert.confidence,
          evidence: alert.evidence || null,
          param: alert.param || null,
          riskCode: alert.riskCode || alert.riskcode,
          sourceRisk: alert.risk,
          sourceTool: 'ZAP',
        },
      };
    });
  }

  /**
   * Perform a complete scan: start, wait, and retrieve results
   */
  async performScan(targetUrl: string, scanDepth: string, onProgress?: (progress: number) => void, abortSignal?: AbortSignal): Promise<ZapScanResult> {
    // Check if ZAP is ready with retry
    const ready = await this.isReady();
    if (!ready) {
      throw new Error("ZAP daemon is not ready. Check that it is running and accessible.");
    }

    // Start a fresh ZAP session to avoid alerts from previous scans polluting results
    try {
      await this.clearSession();
    } catch (e) {
      // non-fatal
    }

    // Configure timeout based on scan depth
    // Deep scans should have much longer timeouts
    let maxWaitMs: number;
    if (scanDepth === "shallow") {
      maxWaitMs = 300000;   // 5 minutes
    } else if (scanDepth === "deep") {
      maxWaitMs = 3600000;  // 60 minutes
    } else {
      maxWaitMs = 1800000;  // 30 minutes for medium (increased from 10)
    }

    try {
      // Start the scan
      const scanId = await this.startScan(targetUrl, scanDepth);

      // Wait for completion with appropriate timeout and pass scanDepth for buffer calculation
      await this.waitForScan(scanId, maxWaitMs, onProgress, abortSignal, scanDepth);

      // Get results - retry if empty for deep scans
      let alerts = await this.getAlerts(scanId, targetUrl);

      // For deep scans, if we get no alerts, wait a moment and try again
      // (sometimes there's a race condition with alert retrieval)
      if (scanDepth === "deep" && alerts.length === 0) {
        console.log(`[ZAP] Deep scan returned no alerts on first try, waiting 5 seconds and retrying...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
        alerts = await this.getAlerts(scanId, targetUrl);
        if (alerts.length === 0) {
          console.log(`[ZAP] Still no alerts after retry - this scan genuinely found no vulnerabilities`);
        }
      }

      const vulnerabilities = this.convertAlertsToVulnerabilities(alerts);

      return { alerts, vulnerabilities };
    } catch (error: any) {
      console.error("[ZAP] Scan failed:", error.message);
      throw error;
    }
  }
}

// Default export for easy import
export const zapClient = new ZapClient();
