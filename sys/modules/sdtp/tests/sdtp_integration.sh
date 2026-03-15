#!/usr/bin/env atf-sh

atf_test_case basic_v4 cleanup
basic_v4_head()
{
    atf_set "descr" "Basic SDTP transfer over two VNET jails"
    atf_set "require.user" "root"
}

basic_v4_body()
{
    atf_require_prog ifconfig
    atf_require_prog jail
    atf_require_prog jexec
    atf_require_prog kldload
    atf_require_prog kldunload
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_send"
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_recv"

    jail -r sdtp_a 2>/dev/null || true
    jail -r sdtp_b 2>/dev/null || true
    pkill -f sdtp_test_recv 2>/dev/null || true
    pkill -f sdtp_test_send 2>/dev/null || true

    # TODO: We want someway to load it automatically
    kldstat -n sdtp >/dev/null 2>&1 || atf_skip "sdtp module is not loaded"
    kldstat -n if_epair >/dev/null 2>&1 || atf_skip "if_epair module is not loaded"

    epair=$(ifconfig epair create) || atf_fail "failed to create epair"
    a=${epair%a}a
    b=${epair%a}b

    jail -c name=sdtp_a persist vnet || atf_fail "failed to create jail sdtp_a"
    jail -c name=sdtp_b persist vnet || atf_fail "failed to create jail sdtp_b"

    ifconfig "${a}" vnet sdtp_a || atf_fail "failed to move ${a} to sdtp_a"
    ifconfig "${b}" vnet sdtp_b || atf_fail "failed to move ${b} to sdtp_b"

    jexec sdtp_a ifconfig "${a}" inet 192.0.2.1/24 up || atf_fail "failed to configure ${a}"
    jexec sdtp_b ifconfig "${b}" inet 192.0.2.2/24 up || atf_fail "failed to configure ${b}"

    jexec sdtp_b "$(atf_get_srcdir)/sdtp_test_recv" -a 192.0.2.2 -p 9000 -n 1000 -q &
    recv_pid=$!

    sleep 1

    atf_check -s exit:0 -o save:send.out -e empty \
        jexec sdtp_a "$(atf_get_srcdir)/sdtp_test_send" -a 192.0.2.2 -p 9000 -n 1000 -m "hello"

    wait "$recv_pid" || atf_fail "receiver exited with failure"

    awk 'BEGIN { for (i = 0; i < 1000; i++) print "hello" }' >exp.out
    atf_check -s exit:0 -o file:exp.out -e empty cat send.out
}

basic_v4_cleanup()
{
    jail -r sdtp_a 2>/dev/null || true
    jail -r sdtp_b 2>/dev/null || true
    ifconfig "${epair}" destroy 2>/dev/null || true
}

atf_init_test_cases()
{
    atf_add_test_case basic_v4
}
