# Haker / Shield

Android app for opt-in DNS filtering with a visible VPN notification and an in-app PIN.

## Build

GitHub Actions builds a debug APK on each push. Open **Actions** and download the `haker-debug-apk` artifact from a completed run.

## Notes

- The DNS filter is a local VPN service and asks Android for VPN permission.
- The app remains visible and can be stopped or uninstalled through normal Android controls.
- DNS filtering depends on the starter list in `app/src/main/assets/blocklist.txt`; add one domain per line.
