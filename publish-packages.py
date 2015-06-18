#!/usr/bin/env python

import sys, os, time
import getopt
import subprocess
# import tempfile
# import shutil
import logging, logging.handlers
# from smtplib import SMTP
# from socket import getfqdn

## @class MonalisaPublisher
#  @brief Publishes a given package on MonALISA
#
#  @todo Actually generate Doxygen documentation
#  @todo Move documentation in place
class MonalisaPublisher(object):

  ## Module version
  __version__ = '0.0.1'

  ## Constructor.
  #
  #  @param param Param description
  def __init__(self, log_debug, log_on_syslog):
    ## Logging facility (use it with `self._log.info()`, etc.)
    self._log = None
    self._init_log(log_debug, True, log_on_syslog)


  ## Initializes the logging facility.
  #
  #  @param debug True enables debug output, False suppresses it
  #  @param log_on_stderr Whether to log on stderr
  #  @param log_on_syslog Whether to log on syslog
  def _init_log(self, debug, log_on_stderr, log_on_syslog):

    self._log = logging.getLogger('MonalisaPublisher')

    msg_fmt_syslog = 'MonalisaPublisher[%d]: %%(levelname)s: %%(message)s' % os.getpid()
    msg_fmt_stderr = '%(asctime)s ' + msg_fmt_syslog
    datetime_fmt = '%Y-%m-%d %H:%M:%S'

    if log_on_stderr == True:
      stderr_handler = logging.StreamHandler(stream=sys.stderr)
      # Date/time only on stderr (syslog already has it)
      stderr_handler.setFormatter( logging.Formatter(msg_fmt_stderr, datetime_fmt) )
      self._log.addHandler(stderr_handler)

    if log_on_syslog == True:
      syslog_handler = self._get_syslog_handler()
      syslog_handler.setFormatter( logging.Formatter(msg_fmt_syslog) )
      self._log.addHandler(syslog_handler)

    if debug:
      self._log.setLevel(logging.DEBUG)
    else:
      self._log.setLevel(logging.INFO)


  ## Gets an appropriate syslog handler for the current operating system.
  #
  #  @return A SysLogHandler, or None on error
  def _get_syslog_handler(self):
    syslog_address = None
    for a in [ '/var/run/syslog', '/dev/log' ]:
      if os.path.exists(a):
        syslog_address = a
        break

    if syslog_address:
      syslog_handler = logging.handlers.SysLogHandler(address=syslog_address)
      return syslog_handler

    return None


  # ## Updates remote repository.
  # #
  # #  @return True on success, False on error
  # def update_repo(self):

  #   self._log.debug('Updating repository')

  #   cmd = [ 'git', 'remote', 'update', '--prune' ]

  #   with open(os.devnull, 'w') as dev_null:
  #     if not self._show_cmd_output:
  #       redirect = dev_null
  #     else:
  #       redirect = None
  #     sp = subprocess.Popen(cmd, stderr=redirect, stdout=redirect, shell=False, cwd=self._git_clone)

  #   rc = sp.wait()

  #   if rc == 0:
  #     self._log.debug('Success updating repository')
  #     return True

  #   self._log.error('Error updating repository, returned %d' % rc)
  #   return False


  ## Entry point for all operations.
  #
  #  @return 0 on success, nonzero on error: can be propagated to the system
  def run(self):

    self._log.info('This is MonalisaPublisher v%s' % self.__version__)
    return 0


# Entry point
if __name__ == '__main__':

  log_debug = False
  log_on_syslog = False

  opts, args = getopt.getopt(sys.argv[1:], '',
    [ 'git-clone=', 'output-path=', 'debug', 'syslog' ])
  for o, a in opts:
    if o == '--debug':
      log_debug = True
    elif o == '--syslog':
      log_on_syslog = True
    else:
      raise getopt.GetoptError('unknown parameter: %s' % o)

  mona = MonalisaPublisher(
    log_debug=log_debug, log_on_syslog=log_on_syslog
  )
  ret = mona.run()
  sys.exit(ret)
