export async function searchNvdCve(cveId: string): Promise<any> {
  const response = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(
      cveId.trim()
    )}`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch CVE from NVD");
  }

  const data = await response.json();

  if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
    throw new Error(`CVE ${cveId} was not found in NVD`);
  }

  return data.vulnerabilities[0].cve;
}