#!/usr/bin/env python

"""Install bpfctrl"""

from setuptools import setup

setup(
    name="bpfctrl",
    version="0.2",
    description="A bpftool wrapper to handle eBPF maps.",
    install_requires=['argparse', 'ipaddress'],
    packages=['bpfctrl'],
    package_dir={'bpfctrl': 'src'},
    scripts=['bpfctrl'],
    provides=['bpfctrl'],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)'
    ],
)
