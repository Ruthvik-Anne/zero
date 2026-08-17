// A plain file-list command (`biome check --write ...<files>`) blows the
// Windows cmd.exe argument-length limit once enough files are staged at
// once (e.g. a large merge). Running biome against the whole repo instead
// of the staged-file list sidesteps that entirely, and costs a few seconds
// even repo-wide, so nothing is lost versus the file-scoped invocation.
export default {
	"*.{ts,tsx,js,mjs,cjs,json}": () => "biome check --write --error-on-warnings .",
};
