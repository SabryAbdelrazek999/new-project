import { storage } from "./storage";
import { zapClient } from "./zap-client";
import type { InsertVulnerability } from "@shared/schema";

interface ScanResult {
  vulnerabilities: InsertVulnerability[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export async function performScan(scanId: string, targetUrl: string, scanType: string): Promise<ScanResult> {
  const vulnerabilities: InsertVulnerability[] = [];
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  try {
    // Validate URL
    const url = new URL(targetUrl);

    // Update scan status to running
    await storage.updateScan(scanId, {
      status: "running",
      startedAt: new Date()
    });

    // Use ZAP daemon to perform the scan
    console.log(`[Scanner] Running ZAP scan for ${targetUrl}`);
    const zapResult = await zapClient.performScan(targetUrl, scanType, async (progress) => {
      // Update scan progress
      await storage.updateScan(scanId, { progress });
    });

    // Convert ZAP vulnerabilities to our format and add scanId
    const zapVulnerabilities = zapResult.vulnerabilities.map((vuln) => ({
      ...vuln,
      scanId,
      affectedUrl: vuln.affectedUrl || targetUrl,
    } as InsertVulnerability));

    vulnerabilities.push(...zapVulnerabilities);

    // Count severities from ZAP results
    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
        case "critical": criticalCount++; break;
        case "high": highCount++; break;
        case "medium": mediumCount++; break;
        case "low": lowCount++; break;
      }
    }

    console.log(`[Scanner] ZAP scan complete: ${vulnerabilities.length} vulnerabilities found (critical: ${criticalCount}, high: ${highCount}, medium: ${mediumCount}, low: ${lowCount})`);

    // Save vulnerabilities to storage first (awaited sequentially to avoid race conditions)
    for (const vuln of vulnerabilities) {
      try {
        await storage.createVulnerability(vuln);
      } catch (err) {
        console.error("Failed to save vulnerability:", err);
      }
    }

    // Update scan with results only after all vulnerabilities are saved
    try {
      await storage.updateScan(scanId, {
        status: "completed",
        completedAt: new Date(),
        totalVulnerabilities: vulnerabilities.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      });
      // create a report entry pointing to the export endpoint
      try {
        const saved = await storage.getScan(scanId);
        if (saved) {
          const total = vulnerabilities.length;
          const critical = criticalCount;
          const high = highCount;
          const medium = mediumCount;
          const low = lowCount;

          await storage.createReport({
            userId: saved.userId,
            scanId: saved.id,
            reportName: `Scan Report - ${saved.targetUrl}`,
            reportPath: `/api/reports/export/${scanId}`,
            createdAt: new Date(),
            total,
            critical,
            high,
            medium,
            low,
          } as any);
        }
      } catch (err) {
        console.error("Failed to create report entry:", err);
      }
    } catch (err) {
      console.error("Failed to update scan status:", err);
    }

  } catch (error: any) {
    // Handle scan errors
    const errorMessage = error.message || "Unknown error occurred";

    try {
      await storage.updateScan(scanId, {
        status: "failed",
        completedAt: new Date(),
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
      });
    } catch (storageError) {
      console.error("Failed to update scan status:", storageError);
    }

    return {
      vulnerabilities: [],
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
    };
  }

  return {
    vulnerabilities,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
  };
}

export async function getLastScanTime(): Promise<string> {
  const scans = await storage.getRecentScans(1);
  if (scans.length === 0) {
    return "Never";
  }
  const lastScan = scans[0];
  if (lastScan.completedAt) {
    const diff = Date.now() - new Date(lastScan.completedAt).getTime();
    if (diff < 60000) return "Just Now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)} min ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return new Date(lastScan.completedAt).toLocaleDateString();
  }
  return "In Progress";
}
