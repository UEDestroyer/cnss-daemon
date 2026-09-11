#include "cnss/daemon.hpp"
#include "cnss/logger.hpp"
#include <getopt.h>
#include <csignal>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>

static void usage(const char* p) {
    std::fprintf(stderr, "usage: %s [options]\n  -n, --nodaemon       stay in foreground\n  -d                    increase debug level\n  -l                    reserved for logcat-compatible mode\n  -s PATH               user socket path\n", p);
}

int main(int argc, char** argv) {
    cnss::Config cfg;
    static const option opts[] = {
        {"nodaemon", no_argument, nullptr, 'n'}, {"help", no_argument, nullptr, 'h'}, {"socket", required_argument, nullptr, 's'}, {nullptr,0,nullptr,0}
    };
    int c;
    while ((c = ::getopt_long(argc, argv, "ndlhs:", opts, nullptr)) != -1) {
        switch (c) {
            case 'n': cfg.daemonize = false; break;
            case 'd': ++cfg.debug_level; break;
            case 'l': break;
            case 's': cfg.user_socket = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }
    if (cfg.daemonize) {
        // The source binary defaults to daemon(0,0); keep that behavior available.
        if (::daemon(0,0) != 0) { std::perror("daemon"); return 1; }
    }
    cnss::Daemon d(cfg);
    struct sigaction sa{}; sigemptyset(&sa.sa_mask); sa.sa_handler = cnss::Daemon::signal_handler;
    sigaction(SIGINT,&sa,nullptr); sigaction(SIGTERM,&sa,nullptr); sigaction(SIGQUIT,&sa,nullptr);
    return d.run();
}
