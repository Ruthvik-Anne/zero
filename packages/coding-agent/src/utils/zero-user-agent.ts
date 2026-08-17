export function getZeroUserAgent(version: string): string {
	const runtime = process.versions.bun ? `bun/${process.versions.bun}` : `node/${process.version}`;
	return `zero/${version} (${process.platform}; ${runtime}; ${process.arch})`;
}
