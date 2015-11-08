#!/usr/bin/env python


from __future__ import absolute_import

# Import python libs
from __future__ import print_function
import os
import sys
import traceback
import logging
import datetime
import traceback
import multiprocessing
import json

import threading
import time
from random import randint

# These imports came from salt/cli/call.py
from salt.utils import parsers
from salt.utils.verify import verify_env, verify_files
from salt.config import _expand_glob_path

import salt.cli.call
import salt.cli.caller

from deepdiff import DeepDiff


usage='''{} [-j] <state1> [state2, state3, etc.]

  -j prints json of the first state provided and then exits.

This script is placed in a subdirectory of your git repo of salt states.
E.g. in a repo called "salt-states" with a subdirectory "states" you
would create a "test" directory called "salt-states/test".  In the test
directory, place this script, a "grains.json" and a "config.json".

The config.json needs to have the key "states_dir" with the path to the
states directory relative to the root of the git repo, like this:

{{
  "states_dir" : "states/"
}}

The trailing "/" is currently important, don't forget it


Each state directory has a test/ directory that will contain a a file
called <statename>.json (one per sls file in the directory) and a single
pillar.json file.

Once a state is rendered via state.show_sls (with the provided grains
and pillars), the test will succeed when all of the keys and values in
the <statename>.json are contained in the output of the test.

The git commit hook to work with this should look like this.  The particulars
of setting up the python environment is going to change from person to person,
I'm using pyenv but activating a virtualenv, or anything along those lines
should work:


# This hook will check the salt states being committed, and confirm that they
# meet the bare minimum qualification of being able to render with the
# provided data.

# Setup the environment for whatever is needed to import the salt package and
# the deepdiff module

. ~/.bash.d/20_pyenv.sh
pyenv shell salt

# Check states
python test/test_salt_state.py $(git diff --cached --name-status | egrep -v '^D' | egrep '.sls$' | awk '{{print $2}}')
RV=$?
exit $RV


'''.format(os.path.basename(sys.argv[0]))

# Import salt libs
from salt.exceptions import SaltSystemExit, SaltClientError, SaltReqTimeoutError
import salt.defaults.exitcodes  # pylint: disable=unused-import

# Custom exceptions
from salt.exceptions import (
    SaltClientError,
    CommandNotFoundError,
    CommandExecutionError,
    SaltInvocationError,
)

log = logging.getLogger(__name__)

class ConfObj(object):
    def __init__(self, conf_dict):
        for k,v in conf_dict.items():
            setattr(self, k, v)
    def __setatrr__(self, name, val):
        setattr(self, name, val)


options = ConfObj({'output_file_append': False,
          'saltfile': None,
          'state_output': 'full',
          'force_color': False,
          'skip_grains': False,
          'config_dir': '/tmp/salt',
          'id': 'foo',
          'output_indent': None,
          'log_level': 'info',
          'output_file': None,
          'module_dirs': [],
          'master': 'salt',
          'log_level_logfile': None,
          'local': True,
          'metadata': False,
          'return': '',
          'no_color': False,
          'pillar_root': '.',
          'hard_crash': False,
#          'file_root': '../../',
          'auth_timeout': 60,
          'refresh_grains_cache': False,
          'doc': False,
          'grains_run': False,
          'versions_report': None,
          'retcode_passthrough': False,
          'output': None,
          'log_file': '/tmp/salt/log',
          'test_conf_dir': '', # Set this once our CWD is determined
})

config = {
    'output_file_append': False,
    'ioflo_realtime': True,
    'master_alive_interval': 0,
    'recon_default': 1000,
    'master_port': '4506',
    'whitelist_modules': [],
    'ioflo_console_logdir': '',
    'utils_dirs': ['/tmp/salt/cache/extmods/utils'],
    'states_dirs': [],
    'fileserver_backend': ['roots'],
    'outputter_dirs': [],
    'sls_list': [],
    'module_dirs': [],
    'extension_modules': '/tmp/salt/cache/extmods',
    'state_auto_order': True,
    'acceptance_wait_time': 10,
    '__role': 'minion',
    'disable_modules': [],
    'backup_mode': '',
    'recon_randomize': True,
    'return': '',
    'file_ignore_glob': None,
    'auto_accept': True,
    'cache_jobs': False,
    'state_verbose': True,
    'verify_master_pubkey_sign': False,
    'password': None,
    'startup_states': '',
    'auth_timeout': 60,
    'always_verify_signature': False,
    'tcp_pull_port': 4511,
    'gitfs_pubkey': '',
    'fileserver_ignoresymlinks': False,
    'retry_dns': 30,
    'file_ignore_regex': None,
    'output': 'json',
    'master_shuffle': False,
    'metadata': False,
    'multiprocessing': True,
    'file_roots': {'base': ['/srv/salt']},
    'root_dir': '/',
    'log_granular_levels': {},
    'returner_dirs': [],
    'gitfs_privkey': '',
    'tcp_keepalive': True,
    'log_datefmt_logfile': '%Y-%m-%d %H:%M:%S',
    'config_dir': '/tmp/salt',
    'random_reauth_delay': 10,
    'autosign_timeout': 120,
    'gitfs_base': 'master',
    'render_dirs': [],
    'gitfs_user': '',
    'fileserver_limit_traversal': False,
    'tcp_keepalive_intvl': -1,
    'pillar_root': '.',
    'top_file': '',
    'zmq_monitor': False,
    'file_recv_max_size': 100,
    'pidfile': '/tmp/salt/salt-minion.pid',
    'range_server': 'range:80',
    'raet_mutable': False,
    'grains_dirs': [],
    'pillar_roots': {'base': ['/srv/pillar']},
    'schedule': {},
    'raet_main': False,
    'fun': 'state.show_sls',
    'cachedir': '/tmp/salt/cache',
    'interface': '0.0.0.0',
    'update_restart_services': [],
    'recon_max': 10000,
    'default_include': 'minion.d/*.conf',
    'hard_crash': False,
    'rejected_retry': False,
    'state_events': False,
    'environment': None,
    'win_repo_cachefile': 'salt://win/repo/winrepo.p',
    'ipc_mode': 'ipc',
    'keysize': 2048,
    'master_sign_key_name': 'master_sign',
    'cython_enable': False,
    'raet_port': 4510,
    'ext_job_cache': '',
    'hash_type': 'md5',
    'state_output': 'full',
    'force_color': False,
    'modules_max_memory': -1,
    'renderer': 'yaml_jinja',
    'state_top': 'top.sls',
    'gitfs_env_whitelist': [],
    'auth_tries': 7,
    'gitfs_insecure_auth': False,
    'mine_interval': 60,
    'grains_cache': False,
    'file_recv': False,
    'log_level_logfile': None,
    'ipv6': False,
    'master': 'salt',
    'sudo_user': '',
    'no_color': False,
    'username': None,
    'master_finger': '',
    'failhard': False,
    'tcp_keepalive_idle': 300,
    'gitfs_passphrase': '',
    'fileserver_followsymlinks': True,
    'verify_env': True,
    'ioflo_period': 0.1,
    'ping_interval': 0,
    'grains': {},
    'local': True,
    'tcp_keepalive_cnt': -1,
    'raet_alt_port': 4511,
    'skip_grains': False,
    'retcode_passthrough': True,
    'doc': False,
    'state_aggregate': False,
    'syndic_log_file': '/var/log/salt/syndic',
    'update_url': False,
    'grains_refresh_every': 0,
    'transport': 'zeromq',
    'providers': {},
    'autoload_dynamic_modules': True,
    'file_buffer_size': 262144,
    'log_fmt_console': '[%(levelname)-8s] %(message)s',
    'random_master': False,
    'log_datefmt': '%H:%M:%S',
    'grains_cache_expiration': 300,
    'minion_floscript': '/Users/peter.norton/.pyenv/versions/salt/lib/python2.7/site-packages/salt/daemons/flo/minion.flo',
    'id': 'foo',
    'syndic_pidfile': '/var/run/salt-syndic.pid',
    'loop_interval': 1,
    'log_level': 'info',
    'gitfs_env_blacklist': [],
    'auth_safemode': False,
    'clean_dynamic_modules': True,
    'disable_returners': [],
    'cache_sreqs': True,
    'minion_id_caching': True,
    'gitfs_root': '',
    'test': False,
    'gitfs_password': '',
    'caller_floscript': '/Users/peter.norton/.pyenv/versions/salt/lib/python2.7/site-packages/salt/daemons/flo/caller.flo',
    'caller': True,
    'syndic_finger': '',
    'raet_clear_remotes': True,
    'file_client': 'local',
    'user': 'root',
    'use_master_when_local': False,
    'acceptance_wait_time_max': 0,
    'open_mode': False,
    'permissive_pki_access': False,
    'cmd_safe': True,
    'zmq_filtering': False,
    'refresh_grains_cache': False,
    'selected_output_option': 'output_indent',
    'master_type': 'standard',
    'pki_dir': '/tmp/salt/pki/minion',
    'grains_run': False,
    'max_event_size': 1048576,
    'ioflo_verbose': 0,
    'sock_dir': '/var/run/salt/minion',
    'tcp_pub_port': 4510,
    'log_fmt_logfile': '%(asctime)s,%(msecs)03.0f [%(name)-17s][%(levelname)-8s][%(process)d] %(message)s',
    'log_file': '/tmp/salt/log',
    'gitfs_remotes': [],
    'gitfs_mountpoint': ''}

def _handle_interrupt(exc, original_exc, hardfail=False, trace=''):
    '''
    if hardfailing:
        If we got the original stacktrace, log it
        If all cases, raise the original exception
        but this is logically part the initial
        stack.
    else just let salt exit gracefully

    '''
    if hardfail:
        if trace:
            log.error(trace)
        raise original_exc
    else:
        raise exc

def salt_call():
    '''
    Directly call state.show_sls via the same mechanism as salt-call
    '''
    global config
    global options
    if '' in sys.path:
        sys.path.remove('')

    try:
        caller = LocalCaller(config)
        return caller.call()
    except KeyboardInterrupt as err:
        trace = traceback.format_exc()
        try:
            hardcrash = client.options.hard_crash
        except (AttributeError, KeyError):
            hardcrash = False
        _handle_interrupt(
            SystemExit('\nExiting gracefully on Ctrl-c'),
            err,
            hardcrash, trace=trace)

class LocalCaller(object):
    '''
    Object to wrap the calling of local salt modules for testing
    Stripping down bits of the ZeroMQCaller
    '''
    def __init__(self, this_config):
        '''
        Pass in the command line options
        '''
        self.config = this_config
        self.serial = salt.payload.Serial(self.config)
        # Handle this here so other deeper code which might
        # be imported as part of the salt api doesn't do  a
        # nasty sys.exit() and tick off our developer users
        global options
        try:
            # grains get loaded below
            # via salt.minion.SMinion, then via salt.loader.grains()
            self.minion = salt.minion.SMinion(config)
            # Then we can overwrite it
            self.minion.opts['grains'] = get_grains_from_file("{}/grains.json".format(options.test_conf_dir))
        except SaltClientError as exc:
            raise SystemExit(str(exc))

    def call(self):
        '''
        Call the module
        '''
        ret = {}
        fun = self.config['fun']
        ret['jid'] = '{0:%Y%m%d%H%M%S%f}'.format(datetime.datetime.now())
        proc_fn = os.path.join(
            salt.minion.get_proc_dir(self.config['cachedir']),
            ret['jid']
        )
        sdata = {
            'fun': fun,
            'pid': os.getpid(),
            'jid': ret['jid'],
            'tgt': 'salt-call'}

        # Args are sanitized or whateverhere, and pillars and
        # grains need to be added back at this point as well
        args, kwargs = salt.minion.load_args_and_kwargs(
            self.minion.functions[fun],
            salt.utils.args.parse_input(self.config['arg']),
            data=sdata)
        pillar_file = '{}/pillar.json'.format(self.config['state_test_dir'])
        try:
            kwargs['pillar'] = json.load(open(pillar_file))
        except IOError as ioe:
            print("Couldn't load sls test pillar file {} because {}".format(pillar_file, ioe))
            kwargs['pillar'] = dict()


        func = self.minion.functions[fun]

        kwargs['options'] = self.config

        try:
            ret['return'] = test_show_sls(func, *args, **kwargs)
        except TypeError as exc:
            trace = traceback.format_exc()
            raise ValueError, 'Passed invalid arguments: {0}\n'.format(exc)
        try:
            ret['retcode'] = sys.modules[
                func.__module__].__context__.get('retcode', 0)
        except AttributeError:
            ret['retcode'] = 1
        return ret


def test_show_sls(func, mods, saltenv='base', test=None, queue=False, **kwargs):
    '''
    The salt.state.show_sls() doesn't provide a way to pass in grains,
    it'll only read them from a minion config if that option is
    provided.  So we will override that specific behavior here.

    Display the state data from a specific sls or list of sls files on the
    master. The default environment is ``base``, use ``saltenv`` (``env`` in
    Salt 0.17.x and older) to specify a different environment.

    This function does not support topfiles.  For ``top.sls`` please use
    ``show_top`` instead.

    Custom Pillar data can be passed with the ``pillar`` kwarg.

    A custom options dictionary (including grains) can be passed with the ``options`` kwarg.

    CLI Example:

    .. code-block:: bash

        salt '*' state.show_sls core,edit.vim dev
    '''
    opts = kwargs.get('options', {})

    pillar = kwargs.get('pillar')

    st_ = salt.state.HighState(opts, pillar)
    st_.push_active()
    try:
        high_, errors = st_.render_highstate({saltenv: [mods]})
    finally:
        st_.pop_active()
    errors += st_.state.verify_high(high_)

    if errors:
        return errors
    return high_


def check_single_state(state):
    '''
    state is a tuple of state name, and path to the state in the repo
    '''
    config['arg'] = [state[0]]
    config['state_test_dir'] = "{}/test".format(os.path.abspath(os.path.dirname(state[1])))
    call_result = salt_call()

    # Given path/to/somestate.sls, create path/to/test/somestate.json
    state_name = state[1].split("/")[-1].split('.')[0]
    desired_filename = "{}/{}.json".format(config['state_test_dir'], state_name)

    test_result = json.loads(json.dumps(call_result['return']))
    desired_result = json.load(open(desired_filename))

    comparison = DeepDiff(test_result, desired_result)
    if comparison:
        print("{} failed".format(state[0]))
        print(comparison)
        return(call_result['retcode'] + 1, call_result['return'])
    else:
        return (call_result['retcode'], call_result['return'])

def print_state_json(state):
    """
    Print out the json representaiton of the state to use as a test result
    """
    global config
    config['arg'] = [state[0]]
    config['state_test_dir'] = "{}/test".format(os.path.abspath(os.path.dirname(state[1])))
    call_result = salt_call()
    print(json.dumps(call_result['return'], sort_keys=True, indent=4))


def get_grains_from_file(fname):
    return json.load(open(fname))


def set_config_and_grains():
    """Sets the global config and options.  The config and options are used to
    feed the salty parts of the configuration.

    This returns the test_conf, which is the deserialized configuration
    from the config.yaml

    """
    global config
    global options
    # The directory where this script lives, and where config will be
    test_conf_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    options.test_conf_dir = test_conf_dir
    with open('{}/config.json'.format(test_conf_dir)) as conf_fh:
        test_conf = json.load(conf_fh)
    config['grains'] = get_grains_from_file('{}/grains.json'.format(test_conf_dir))

    # Configure the file_roots now that we have our configuration loaded
    options.file_root = os.path.abspath("{}/../{}".format(test_conf_dir, test_conf['states_dir']))
    config['file_roots'] = {'base': [options.file_root]}
    return test_conf

def main():
    accumulated_rc = 0
    test_conf = set_config_and_grains()


    statedir_offset = len(test_conf['states_dir'])

    if len(sys.argv) > 1:
        if sys.argv[1] == '-h':
            exit_usage()

        if sys.argv[1] == '-j': # print json instead of testing
            state_paths = sys.argv[2:]
        else:
            state_paths = sys.argv[1:]

        # list of (state, relative path)
        states_list = [ (s.replace("/", ".")[statedir_offset:-4], s) for s in state_paths
                        if s.startswith(test_conf['states_dir'])]
        for s in states_list:
            if sys.argv[1] == '-j':
                print_state_json(s) # Do no checking
                break # and only process one state, and only produce one document
            else:
                retcode, retval = check_single_state(s)
                accumulated_rc += retcode
    else:
        sys.exit(0)
    # Be exhaustive and check all of the configuration(s)
    sys.exit(accumulated_rc) # git likes 0, git rejects non-zero

def exit_usage():
    print(usage)
    sys.exit(2)


if __name__ == '__main__':
    main()
