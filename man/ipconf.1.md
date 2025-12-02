<!--
.\" Copyright (C) 2025 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

ipconf(1) -- configure network interfaces using iothconf configuration
strings

# SYNOPSIS

`ipconf` [OPTIONS] [*iothconf_string*] [*iothconf_string*]  ...

# DESCRIPTION

`ipconf` provides  a  simple way to configure networking stacks.
All the configuration parameters are  specified  by  a  character string
as described in iothconf(3)

# OPTIONS
  `-v`, `--verbose`
: print an acknowlegment for each configuration string.

# SEE ALSO
iothconf(3)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
