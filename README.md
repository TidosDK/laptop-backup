# system-backup

An application that backs up selected paths on your UNIX file system.

## Usage

To use the application, two files must be created.

- A `paths.txt` file, including the path to directories for backing up (does not work with files, only directores).

Example of a `paths.txt` file:

```
/home/user/.ssh/
/home/user/Projects/
/home/user/Documents/
```

- A `public_key.txt` file, including a public key of age X25519.

Example of a `public_key.txt` file:

```
age1qfvum86j3xuqw9zx7km5kyd7rp3z0r0fwaptmu8ravslf8cls7nslmaqk5
```

---

After both `.txt` files have been configured, the application can run.

## Missing features

- Ignore specified paths in paths.txt
