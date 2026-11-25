// Never answers: --probe must give up after its timeout. It also exits on its own after 20 seconds,
// so a broken probe (as in mutation testing) cannot leave it running.
setTimeout(() => process.exit(0), 20000);
