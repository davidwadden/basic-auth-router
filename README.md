## Basic Auth Router

This is a CF route service inspired from https://github.com/benlaplanche/cf-basic-auth-route-service

### Install

- Requires [dep](https://github.com/golang/dep) for dependency management  

```bash
$ dep ensure

$ go build

$ ./basic-auth-router
```

### Configure

The following environment variables set the credentials:

```
BASIC_AUTH_USERNAME
BASIC_AUTH_PASSWORD
```

> Default credentials are `user` / `password`
