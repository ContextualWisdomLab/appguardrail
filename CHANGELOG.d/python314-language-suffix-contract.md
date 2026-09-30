### Fixed

- Language detection now applies one filename-suffix contract to string and
  `Path` inputs on Python 3.13 and 3.14, preserving detection for unusual but
  valid source names such as `....py`.
