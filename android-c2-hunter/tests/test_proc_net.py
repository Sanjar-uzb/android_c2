from hunter.sockets import parse_proc_net


def test_parse_proc_net_basic():
    text = '''sl  local_address rem_address   st uid inode
    0: 0100007F:1F90 0100007F:1F90 01 1000 1234
    '''
    rows = parse_proc_net(text, 'tcp')
    assert len(rows) == 1
    assert rows[0]['proto'] == 'tcp'
    assert rows[0]['local_port'] == 8080
    assert rows[0]['remote_port'] == 8080
