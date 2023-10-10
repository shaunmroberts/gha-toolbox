const core = require("@actions/core");
const github = require("@actions/github");

async function run() {
    const token = core.getInput("repo-token", { required: true });
    const branchName = core.getInput("branch_name", { required: true });
    console.log(`Branch Name: ${branchName}`);

    const client = new github.getOctokit(token);
    const prs = await client.rest.pulls.list({
        repo: github.context.payload.repository.name,
        owner: github.context.payload.repository.owner.login,
        head: `TonicAI:${branchName}`,
    });
    if (!prs.data || !prs.data.length) {
        throw new Error(`Pull request not found for branch ${branchName}`);
    }

    prNumber = prs.data[0].number;
    if (!prNumber) {
        throw new Error(`Pull request not found for branch ${branchName}`);
    }

    console.log(`PR Number: ${prNumber}`);
    core.setOutput("pr_number", prNumber);
    console.log(`PR State: ${prs.data[0].state}`);
    core.setOutput("state", prs.data[0].state);
    console.log(`PR Draft Status: ${prs.data[0].draft}`);
    core.setOutput("draft", prs.data[0].draft);
    console.log(`PR Description: ${prs.data[0].body}`);
    core.setOutput("pr_description", prs.data[0].body);
}

run().catch((error) => {
    core.setFailed(error.message);
    if (error instanceof Error && error.stack) {
        core.debug(error.stack);
    }
});
