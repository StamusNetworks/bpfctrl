#!/usr/bin/env python

"""Install bpfctrl"""

from setuptools import setup

setup(
    name="bpfctrl",
    version="0.1",
    description="A bpftool wrapper to handle eBPF maps.",
    install_requires=['argparse', 'ipaddress'],
    packages=['bpfctrl'],
    scripts=['bpfctrl/bpfctrl'],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)'
    ],
)
