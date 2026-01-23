import axios from "axios";

interface ZapAlert {
  id: string;
  pluginId: string;
  pluginName: string;
  name: string;
  description: string;
  solution: string;
  riskcode: string;
  confidence: string;
  riskdesc: string;
  confidencedesc: string;
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
  private client = axios.create();

  constructor(baseUrl?: string) {
    // Use environment variable with fallback
    this.baseUrl = baseUrl || process.env.ZAP_API_URL || "http://zap:8080";
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
   * Start an active scan on the target URL
   * Returns scan ID
   */
  async startScan(targetUrl: string, profile: string = "quick"): Promise<string> {
    try {
      console.log(`[ZAP] Starting active scan for ${targetUrl}`);

      // First, add URL to context
      const encodedUrl = encodeURIComponent(targetUrl);

      // Step 1: Access the URL first (important!)
      try {
        await this.client.get(
          `${this.baseUrl}/JSON/core/action/accessUrl?url=${encodedUrl}`,
          { timeout: 30000 }
        );
        console.log(`[ZAP] ✅ URL accessed: ${targetUrl}`);
      } catch (err) {
        console.log(`[ZAP] ⚠️  Could not access URL directly, continuing...`);
      }

      // Step 2: Spider the target (optional but recommended)
      try {
        const maxChildren = profile === "full" ? 0 : 10;
        const spiderResponse = await this.client.get(
          `${this.baseUrl}/JSON/spider/action/scan?url=${encodedUrl}&maxChildren=${maxChildren}&recurse=true`,
          { timeout: 30000 }
        );
        const spiderScanId = spiderResponse.data.scan;
        console.log(`[ZAP] Spider started with ID: ${spiderScanId}`);

        // Wait for spider to complete
        await this.waitForSpider(spiderScanId);
      } catch (err: any) {
        console.log(`[ZAP] ⚠️  Spider failed or timed out: ${err.message}, continuing with active scan...`);
      }

      // Step 3: Start active scan (removed inScopeOnly parameter)
      const response = await this.client.get(
        `${this.baseUrl}/JSON/ascan/action/scan?url=${encodedUrl}&recurse=true`,
        { timeout: 30000 }
      );

      const scanId = response.data.scan;
      console.log(`[ZAP] ✅ Active scan started with ID: ${scanId}`);
      return String(scanId);
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
  async waitForSpider(scanId: string, maxWaitMs: number = 300000): Promise<void> {
    const startTime = Date.now();
    const pollInterval = 5000; // 5 seconds

    while (Date.now() - startTime < maxWaitMs) {
      try {
        const response = await this.client.get(
          `${this.baseUrl}/JSON/spider/view/status?scanId=${scanId}`,
          { timeout: 15000 }
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

    throw new Error(`ZAP spider ${scanId} did not complete within ${maxWaitMs}ms`);
  }

  /**
   * Poll scan status until completion
   * Progress is 0-100
   */
  async waitForScan(scanId: string, maxWaitMs: number = 600000, onProgress?: (progress: number) => void): Promise<void> {
    const startTime = Date.now();
    const pollInterval = 10000; // 10 seconds

    while (Date.now() - startTime < maxWaitMs) {
      try {
        const response = await this.client.get(
          `${this.baseUrl}/JSON/ascan/view/status?scanId=${scanId}`,
          { timeout: 15000 }
        );
        const progress = parseInt(response.data.status, 10);
        console.log(`[ZAP] Scan ${scanId} progress: ${progress}%`);

        if (onProgress) {
          onProgress(progress);
        }

        if (progress === 100) {
          console.log(`[ZAP] ✅ Scan ${scanId} completed`);
          return;
        }

        // Wait before polling again
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      } catch (error: any) {
        console.error(`[ZAP] Error polling scan status:`, error.message);
        // Continue trying instead of throwing error immediately
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(`ZAP scan ${scanId} did not complete within ${maxWaitMs}ms`);
  }

  /**
   * Retrieve all alerts for a scan
   */
  async getAlerts(scanId?: string): Promise<ZapAlert[]> {
    try {
      const baseParam = scanId ? `?scanId=${scanId}` : "";
      const response = await this.client.get(
        `${this.baseUrl}/JSON/core/view/alerts${baseParam}`,
        { timeout: 15000 }
      );

      const alerts: ZapAlert[] = response.data.alerts || [];
      console.log(`[ZAP] Retrieved ${alerts.length} alerts`);
      return alerts;
    } catch (error: any) {
      console.error("[ZAP] Failed to get alerts:", error.message);
      // لا ترمي خطأ، ارجع مصفوفة فارغة
      return [];
    }
  }

  /**
   * Convert ZAP alerts to our vulnerability format
   */
  convertAlertsToVulnerabilities(alerts: ZapAlert[]): ZapScanResult["vulnerabilities"] {
    const riskMap: Record<string, "critical" | "high" | "medium" | "low"> = {
      "3": "critical",
      "2": "high",
      "1": "medium",
      "0": "low",
    };

    return alerts.map((alert) => ({
      type: alert.pluginName || alert.name,
      severity: (riskMap[alert.riskcode] || "low") as "critical" | "high" | "medium" | "low",
      title: alert.name,
      description: alert.description,
      affectedUrl: alert.url,
      remediation: alert.solution,
      details: {
        pluginId: alert.pluginId,
        confidence: alert.confidencedesc,
        evidence: alert.evidence || null,
        param: alert.param || null,
      },
    }));
  }

  /**
   * Perform a complete scan: start, wait, and retrieve results
   */
  async performScan(targetUrl: string, profile: string, onProgress?: (progress: number) => void): Promise<ZapScanResult> {
    // Check if ZAP is ready with retry
    const ready = await this.isReady();
    if (!ready) {
      throw new Error("ZAP daemon is not ready. Check that it is running and accessible.");
    }

    try {
      // Start the scan
      const scanId = await this.startScan(targetUrl, profile);

      // Wait for completion
      await this.waitForScan(scanId, 600000, onProgress);

      // Get results
      const alerts = await this.getAlerts(scanId);
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