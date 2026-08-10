project(susshi-shared C)

# Sources
set(shared_SRCS
        base64.c
        bastion-sshd.c
        hash.c
        hexdump.c
        log-enc.c
        memcrypt.c
        misc.c
        paseto.c
        privileges.c
        processes.c
        wrappers.c
        cidr.c
)

add_library(susshi-shared STATIC ${shared_SRCS})

