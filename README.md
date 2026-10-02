# NetVanta 1.0.0

Dashboard web untuk pemeriksaan jaringan yang dapat dideploy ke Vercel tanpa database.

## Deploy
1. Upload folder ini ke repository Git.
2. Import repository ke Vercel.
3. Framework Preset: Other.
4. Build Command: kosongkan.
5. Output Directory: `.`.
6. Deploy.

## Fitur
- Cek IP website: DNS lookup URL.
- Scan server IP: DNS lookup + HTTP HEAD probe.
- Cek open port: TCP connect terhadap daftar port umum terbatas.
- Scan WiFi: pemeriksaan exposure berbasis IP/port. Vercel tidak bisa mengakses radio WiFi/LAN lokal pengguna dan tidak melakukan brute-force password.
- Network traffic: live TCP probe berkala terhadap IP:PORT. Ini bukan packet capture seperti Wireshark.
- Special IP Scan: Coming soon.

Gunakan hanya terhadap sistem yang Anda miliki atau yang memberi izin pengujian.
