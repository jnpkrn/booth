#!/usr/bin/python
# vim: fileencoding=utf-8
# see http://stackoverflow.com/questions/728891/correct-way-to-define-python-source-code-encoding

import os, sys, time, signal, tempfile, socket, posix, time
import re, shutil, pexpect, logging
import random, copy, glob, traceback


# Don't make that much sense - function/line is write().
# Would have to use traceback.extract_stack() manually.
#   %(funcName)10.10s:%(lineno)3d  %(levelname)8s 
default_log_format = '%(asctime)s: %(message)s'
default_log_datefmt = '%b %d %H:%M:%S'


# {{{ pexpect-logging glue
# needed for use as pexpect.logfile, to relay into existing logfiles
class expect_logging():
    prefix = ""
    test = None

    def __init__(self, pre, inst):
        self.prefix = pre
        self.test = inst

    def flush(self, *arg):
        pass
    def write(self, stg):
        if self.test.dont_log_expect == 0:
            # TODO: split by input/output, give program
            for line in re.split(r"[\r\n]+", stg):
                if line == self.test.prompt:
                    continue
                if line == "":
                    continue
                logging.debug("  " + self.prefix + "  " + line)
# }}}


# {{{ dictionary plus second hash
class dict_plus(dict):
    def __init__(self):
        self.aux = dict()

#    def aux(self):
#        return self.aux
# }}}


class UT():
# {{{ Members
    binary = None
    test_base = None
    lockfile = None

    defaults = None

    this_port = None
    this_site = "127.0.0.1"
    this_site_id = None

    gdb = None
    booth = None
    prompt = "CUSTOM-GDB-PROMPT-%d-%d" % (os.getpid(), time.time())

    dont_log_expect = 0

    udp_sock = None
# }}}


# {{{ setup functions
    @classmethod
    def _filename(cls, desc):
        return "/tmp/booth-unittest.%s" % desc
        return "/tmp/booth-unittest.%d.%s" % (os.getpid(), desc)


    def __init__(self, bin, dir):
        self.binary = os.path.realpath(bin)
        self.test_base = os.path.realpath(dir) + "/"
        self.defaults = self.read_test_input(self.test_base + "_defaults.txt", state="ticket")
        self.lockfile = UT._filename("lock")
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def read_test_input(self, file, state=None, m = dict()):
        fo = open(file, "r")
        state = None
        for line in fo.readlines():
            # comment?
            if re.match(r"^\s*#", line):
                continue
            # empty line
            if re.match(r"^\s*$", line):
                continue

            # message resp. ticket
            # We allow a comment to have something to write out to screen
            res = re.match(r"^\s*(\w+)\s*:(?:\s*(#.*?\S))?\s*$", line)
            if res:
                state = res.group(1)
                if not m.has_key(state):
                    m[state] = dict_plus()
                if res.group(2):
                    m[state].aux["comment"] = res.group(2)
                continue

            assert(state)

            res = re.match(r"^\s*(\S+)\s*(.*)\s*$", line)
            if res:
                m[state][ res.group(1) ] = res.group(2)
        return m


    def setup_log(self, **args):
        global default_log_format
        global default_log_datefmt

        this_test_log = logging.FileHandler( mode = "w", **args )
        this_test_log.setFormatter(
                logging.Formatter(fmt = default_log_format,
                    datefmt = default_log_datefmt) )
        
        this_test_log.emit(
                logging.makeLogRecord( { 
                    "msg": "## vim: set ft=messages : ##",
                    "lineno": 0,
                    "levelname": "None",
                    "level": None,} ) )

        # in the specific files we want ALL information
        this_test_log.setLevel(logging.DEBUG)

        logging.getLogger('').addHandler(this_test_log)
        return this_test_log


    # We want shorthand in descriptions, ie. "state"
    # instead of "booth_conf->ticket[0].state".
    def translate_shorthand(self, name, context):
        if context == 'ticket':
            return "booth_conf->ticket[0]." + name
        if context == 'message':
            return "msg->" + name
        assert(False)




    def stop_processes(self):
        if os.access(self.lockfile, os.F_OK):
            os.unlink(self.lockfile)
        # In case the boothd process is already dead, isalive() would still return True
        # (because GDB still has it), but terminate() does fail.
        # So we just quit GDB, and that might take the boothd with it -
        # if not, we terminate it ourselves.
        if self.gdb:
            self.gdb.close( force=True );
        if self.booth:
            self.booth.close( force=self.booth.isalive() )


    def start_a_process(self, bin, **args):
        name = re.sub(r".*/", "", bin)
        # How to get stderr, too?
        expct = pexpect.spawn(bin,
                env = dict( os.environ.items() +
                    [('PATH',
                        self.test_base + "/bin/:" +
                        os.getenv('PATH')),
                    ('LC_ALL', 'C'),
                    ('LANG', 'C')] ),
                timeout = 30,
                maxread = 32768,
                **args)
        expct.setecho(False)
        expct.logfile_read = expect_logging("<-  %s" % name, self)
        expct.logfile_send = expect_logging(" -> %s" % name, self)
        return expct


    def start_processes(self):
        self.booth = self.start_a_process(self.binary,
                args = [ "daemon", "-D",
                    "-c", self.test_base + "/booth.conf",
                    "-s", "127.0.0.1",
                    "-l", self.lockfile,
                ])
        logging.info("started booth with PID %d, lockfile %s" % (self.booth.pid, self.lockfile))
        self.booth.expect("BOOTH site daemon is starting", timeout=2)
        #print self.booth.before; exit

        self.gdb = self.start_a_process("gdb",
                args=["-quiet",
                    "-p", str(self.booth.pid),
                    "-nx", "-nh",   # don't use .gdbinit
                    ])
        logging.info("started GDB with PID %d" % self.gdb.pid)
        self.gdb.expect("(gdb)")
        self.gdb.sendline("set pagination off\n")
        self.gdb.sendline("set interactive-mode off\n")
        self.gdb.sendline("set verbose off\n") ## sadly to late for the initial "symbol not found" messages
        self.gdb.sendline("set prompt " + self.prompt + "\\n\n");
        self.sync(2000)
        #os.system("strace -o /tmp/sfdgs -f -tt -s 2000 -p %d &" % self.gdb.pid)

        self.this_site_id = self.query_value("local->site_id")
        self.this_port = int(self.query_value("booth_conf->port"))

        # do a self-test
        self.check_value("local->site_id", self.this_site_id);
        
        # Now we're set up.
        self.send_cmd("break ticket_cron")
        self.send_cmd("break booth_udp_send")
        self.send_cmd("break booth_udp_broadcast")
        self.send_cmd("break recvfrom")
# }}}


# {{{ GDB communication
    def sync(self, timeout=-1):
        self.gdb.expect(self.prompt, timeout)

        answer = self.gdb.before

        self.dont_log_expect += 1
        # be careful not to use RE characters like +*.[] etc.
        r = str(random.randint(2**19, 2**20))
        self.gdb.sendline("print " + r)
        self.gdb.expect(r, timeout)
        self.gdb.expect(self.prompt, timeout)
        self.dont_log_expect -= 1
        return answer    # send a command to GDB, returning the GDB answer as string.

    def send_cmd(self, stg, timeout=-1):
        # give booth a chance to get its messages out
        try:
            self.booth.read_nonblocking(64*1024, 0)
        except pexpect.TIMEOUT:
            pass
        finally:
            pass

        self.gdb.sendline(stg)
        return self.sync(timeout=timeout)

    def _query_value(self, which):
        val = self.send_cmd("print " + which)
        cleaned = re.search(r"^\$\d+ = (.*\S)\s*$", val, re.MULTILINE)
        if not cleaned:
            self.user_debug("query failed")
        return cleaned.group(1)

    def query_value(self, which):
        res = self._query_value(which)
        logging.debug("query_value: «%s» evaluates to «%s»" % (which, res))
        return res

    def check_value(self, which, value):
        val = self._query_value("(" + which + ") == (" + value + ")")
        logging.debug("check_value: «%s» is «%s»: %s" % (which, value, val))
        if val == "1":
            return True
        # for easier (test) debugging we'll show the _real_ value, too.
        has = self._query_value(which)
        logging.error("«%s»: expected «%s», got «%s»." % (which, value, has))
        sys.exit(1)

    # Send data to GDB, to inject them into the binary.
    # Handles different data types
    def set_val(self, name, value, numeric_conv=None):
        logging.debug("setting value «%s» to «%s» (num_conv %s)" %(name, value, numeric_conv))
        # string value?
        if re.match(r'^"', value):
            self.send_cmd("print strcpy(" + name + ", " + value + ")")
        # numeric
        elif numeric_conv:
            self.send_cmd("set variable " + name + " = " + numeric_conv + "(" + value + ")")
        else:
            self.send_cmd("set variable " + name + " = " + value)
        logging.debug("set_val %s done" % name)
# }}} GDB communication


    # there has to be some event waiting, so that boothd stops again.
    def continue_debuggee(self, timeout=30):
        return self.send_cmd("continue", timeout)


# {{{ High-level functions.
# Generally, GDB is attached to BOOTHD, and has it stopped.
    def set_state(self, kv):
        #os.system("strace -f -tt -s 2000 -e write -p" + str(self.gdb.pid) + " &")
        for n, v in kv.iteritems():
            self.set_val( self.translate_shorthand(n, "ticket"), v)
        logging.info("set state")


    def user_debug(self, txt):
        print self.gdb.buffer
        print "\n\nProblem detected (%s), entering interactive mode.\n\n" % txt
        # can't use send_cmd, doesn't reply with expected prompt anymore.
        self.gdb.interact()
        #while True:
        #    sys.stdout.write("GDB> ")
        #    sys.stdout.flush()
        #    x = sys.stdin.readline()
        #    if not x:
        #        break
        #    self.send_cmd(x)
        self.gdb.sendline("set prompt GDB> \n")
        self.gdb.setecho(True)
        self.stop_processes()
        sys.exit(0)
 

    def wait_for_function(self, fn):
        while True:
            stopped_at = self.continue_debuggee(timeout=3)
            if not stopped_at:
                self.user_debug("Not stopped at any breakpoint?")
            if re.search(r"^Program received signal SIGSEGV,", stopped_at, re.MULTILINE):
                self.user_debug("Segfault")
            if re.search(r"^Breakpoint \d+, (0x\w+ in )?%s " % fn, stopped_at, re.MULTILINE):
                break
        logging.info("Now in %s" % fn)

    # We break, change the data, and return the correct size.
    def send_message(self, msg):
        self.udp_sock.sendto('a', (socket.gethostbyname(self.this_site), self.this_port))

        self.wait_for_function("recvfrom")
        # drain input, but stop afterwards for changing data
        self.send_cmd("finish")
        # step over length assignment
        self.send_cmd("next")
        
        # push message.
        for (n, v) in msg.iteritems():
            self.set_val( "msg->" + n, v, "htonl")

        # set "received" length
        self.set_val("rv", "msg->header.length", "ntohl")

        # the next thing should run continue via wait_for_function
 
    def wait_outgoing(self, msg):
        self.wait_for_function("booth_udp_send")
        for (n, v) in msg.iteritems():
            self.check_value( "ntohl(((struct boothc_ticket_msg *)buf)->" + n + ")", v)
        logging.info("out gone")
        #stopped_at = self.sync() 

    def merge_dicts(self, base, overlay):
        return dict(base.items() + overlay.items())
       

    def loop(self, data):
        matches = map(lambda k: re.match(r"^(outgoing|message)(\d+)$", k), data.iterkeys())
        valid_matches = filter(None, matches)
        nums = map(lambda m: int(m.group(2)), valid_matches)
        loop_max = max(nums)
        for counter in range(0, loop_max+1):    # incl. last message
            logging.info("Part " + str(counter))

            kmsg = 'message%d' % counter
            msg  = data.get(kmsg)
            if msg:
                comment = msg.aux.get("comment") or ""
                logging.info("sending " + kmsg + "  " + comment)
                self.send_message(self.merge_dicts(data["message"], msg))
            kout = 'outgoing%d' % counter
            out  = data.get(kout)
            if out:
                logging.info("waiting for " + kout)
                self.wait_outgoing(out)
        logging.info("loop ends")

    def do_finally(self, data):
        if not data:
            return

        # Allow debuggee to reach a stable state
        time.sleep(1)
        # stop it
        posix.kill(self.booth.pid, signal.SIGINT)
        # sync with GDB
        self.query_value("42")

        for (n, v) in data.iteritems():
            self.check_value( "booth_conf->ticket[0]." + n, v)
        

    def run(self):
        os.chdir(self.test_base)
        # TODO: sorted, random order
        for f in filter( (lambda f: re.match(r"^\d\d\d_.*\.txt$", f)), glob.glob("*")):
            log = None
            try:
                log = self.setup_log(filename = UT._filename(f))

                log.setLevel(logging.DEBUG)
                logging.warn("running test %s" % f)
                self.start_processes()

                test = self.read_test_input(f, m=copy.deepcopy(self.defaults))
                self.set_state(test["ticket"])
                self.loop(test)
                self.do_finally(test.get("finally"))
                logging.warn("test %s ends" % f)
            except:
                logging.error("Broke in %s: %s" % (f, sys.exc_info()))
                for frame in traceback.format_tb(sys.exc_traceback):
                    logging.info("  -  %s " % frame.rstrip())
            finally:
                self.stop_processes()
                if log:
                    log.close()
            return
# }}}


##
##class Message(UT):
##    def set_break():
##        "message_recv"
##
##    # set data, with automatic htonl() for network messages.
##    def send_vals(self, data):
##        for n, v in data.iteritems():
##            self.set_val("msg->" + n, v, "htonl")
##
##class Ticket(UT):
##    # set ticket data - 
##    def send_vals(self, data):
##        for (n, v) in data:
##            self.set_val(n, v)

#def traceit(frame, event, arg):
#     if event == "line":
#         lineno = frame.f_lineno
#         print frame.f_code.co_filename, ":", "line", lineno
#     return traceit


# {{{ main 
if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.stderr.write("Must be run non-root; aborting.\n")
        sys.exit(1)


    ut = UT(sys.argv[1], sys.argv[2] + "/")

    # "master" log object needs max level
    logging.basicConfig(level = logging.DEBUG,
            filename = "/dev/null",
            filemode = "a",
            format = default_log_format,
            datefmt = default_log_datefmt)


    overview_log = ut.setup_log( filename = UT._filename('seq') )
    overview_log.setLevel(logging.WARN)

    # http://stackoverflow.com/questions/9321741/printing-to-screen-and-writing-to-a-file-at-the-same-time
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(' #  %(message)s'))
    console.setLevel(logging.WARN)
    logging.getLogger('').addHandler(console)

 
    logging.info("Starting boothd unit tests.")

    #sys.settrace(traceit)

    ret = ut.run()
    sys.exit(ret)
# }}}
