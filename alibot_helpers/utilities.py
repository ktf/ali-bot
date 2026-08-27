#!/usr/bin/env python

import shlex
import sys


def strip_env_comments(text):
    """Drop whole-line # comments from a .env file body.

    Done here rather than by shlex, which offers only two bad options: with
    comments=True a bare '#' inside an UNQUOTED value truncates it, and with
    comments=False the comment text is tokenised as shell words -- so a lone
    apostrophe in prose ("the day's tag") opens a quotation that never closes,
    shlex raises "No closing quotation", and the whole file yields nothing.

    That failure is silent where it matters: list-branch-pr drops the check from
    its listing, the claim loop skips the container on an empty row set, and the
    check simply stops being built with no error anywhere. It cost this repo a
    ubuntu2204 queue for an afternoon, and had two release *.env files in the
    same state.

    Only lines whose first non-blank character is '#' are removed, so a '#'
    inside a value keeps working. A comment cannot start mid-line, which matches
    every *.env here; a line inside a multi-line quoted value that began with
    '#' would be dropped, which nothing does and which a value would have to go
    out of its way to hit.
    """
    return "\n".join("" if line.lstrip().startswith("#") else line
                      for line in text.splitlines())


def parse_env_file(env_file_path):
    '''Parse variable assignments from a .env file.'''
    with open(env_file_path) as envf:
        for token in shlex.split(strip_env_comments(envf.read()), comments=False):
            var, is_assignment, value = token.partition('=')
            if is_assignment:
                yield (var, value)


def to_unicode(s):
    if isinstance(s, bytes):
        return s.decode("utf-8")  # to get newlines as such and not as escaped \n
    return str(s)
