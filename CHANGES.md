# node-ldapauth Changelog

## 2.2.1

- Fix a bug where ldapauth `authenticate()` would raise an example on an empty
  username.


## 2.2.0

- Update to latest ldapjs (0.5.6) and other deps.
  Note: This makes ldapauth only work with node >=0.8 (because of internal dep
  in ldapjs 0.5).


## 2.1.0

- Update to ldapjs 0.4 (from 0.3). Crossing fingers that this doesn't cause breakage.


## 2.0.0

- Add `make check` for checking jsstyle.
- [issue #1] Update to bcrypt 0.5. This means increasing the base node from 0.4
  to 0.6, hence the major version bump.


## 1.0.2

First working version.


