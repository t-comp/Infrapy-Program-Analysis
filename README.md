# InfraPy Detection Analysis
**COM S 4130 Program Analysis — Iowa State University**  
**Team Members: Taylor Bauer, Abby Van Der Brink, Trevor List**

## Overview

In this project, we use static analysis and testing to create query system for questions regarding our program under analysis such as data dependecies, control flow, fuzzing, and other questions. Our analysis was applied to the infrapy/detection module from InfraPy. Infrapy is a a Python program that was developed by developed by Los Alamos National Laboratory (LANL) for nuclear treaty monitoring. The program detects infrasonic soundwaves from nuclear detonations using the Adaptive Fisher Detector (AFD).

# Program Under Analysis

- **InfraPy Repository:** https://github.com/LANL-Seismoacoustics/infrapy
- **Primary file:** beamforming_new.py
- **Target functions:** run_fd, calc_det_thresh, run_fk, find_peaks

## Query UI
 
The easiest way to interact with the query system is through the provided HTML frontend. Open the HTML file in a browser using Live Server, type a natural language question in the search bar, and click run.

For full details on the analysis, setup, and query system design, please reference the [final project design document.](/docs/
