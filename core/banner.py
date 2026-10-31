from core.config import R, R2, R3, B, B2, W, W2, Y, O, G, C, M, D, D2, N, BOLD

def show_banner():
    print(f"""
{G}  _  _  ___  ___  ___ {R}  ___  _  _  ___ _    _    {N}
{G} | \\| |/ _ \\|   \\| __|{R} |__ \\| || || __| |  | |   {N}
{G} | .` | (_) | |) | _| {R}  / /| __ || _|| |__| |__ {N}
{G} |_|\\_|\\___/|___/|___|{R} |___|_||_||___|____|____|{N}

  {D}┌{'─'*62}┐{N}
  {D}│{N}                                                              {D}│{N}
  {D}│{N}  {G}{BOLD}NODE{N}{R}{BOLD}2{N}{B}{BOLD}SHELL{N}  {W2}Node.js Vulnerability Scanner{N}               {D}│{N}
  {D}│{N}                                                              {D}│{N}
  {D}│{N}  {D2}Version  :{W} 1.0{N}                                              {D}│{N}
  {D}│{N}  {D2}Author   :{W} maxod{N}                                            {D}│{N}
  {D}│{N}  {D2}Platform :{W} Kali Linux {R2}+{W} Termux{N}                             {D}│{N}
  {D}│{N}  {D2}Engine   :{W} Pure Python {D2}(zero deps){N}                          {D}│{N}
  {D}│{N}                                                              {D}│{N}
  {D}│{N}  {G}Recon{D2} ▸ {R2}Express{D2} ▸ {O}NoSQL{D2} ▸ {B}Proto{D2} ▸ {B2}JWT{D2} ▸ {Y}SSRF{D2} ▸ {M}GQL{D2} ▸ {C}SSTI{N} {D}│{N}
  {D}│{N}                                                              {D}│{N}
  {D}│{N}  {D2}Authorized testing only.{N}                                    {D}│{N}
  {D}│{N}                                                              {D}│{N}
  {D}└{'─'*62}┘{N}
""")
