# -*- coding: utf-8 -*-
# Fill the undefined bytes of ACNH class structures with the fields their methods access.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys
script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.fields import run_fields
run_fields(currentProgram, monitor, emit=println)
