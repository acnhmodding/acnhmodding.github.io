# -*- coding: utf-8 -*-
# Import bundled ACNH 3.0 save payload structures and resolved hash names.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys

script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.save import run
run(currentProgram, monitor, script_directory, emit=println)
