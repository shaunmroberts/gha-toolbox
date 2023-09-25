const { exec } = require("child_process");

function run(cmd) {
    exec(cmd, (error, stdout, stderr) => {
        if (stdout.length != 0) {
            console.log(`${stdout}`);
        }
        if (stderr.length != 0) {
            console.error(`${stderr}`);
        }
        if (error) {
            process.exitCode = error.code;
            console.error(`${error}`);
            if (error instanceof Error && error.stack) {
                console.error(error.stack);
            }
        }
    });
}

run("sh ./github/connect-to-vpn/connect.sh");
