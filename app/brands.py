"""Small, verified P0 brand mapping. Never infer a brand from page content.

NAVER's corporate service page links https://www.naver.com/:
https://www.navercorp.com/service/portal (verified during integration).
New brand IDs require verification before adding their official eTLD+1.
"""

OFFICIAL_BRAND_DOMAINS = {"naver": "naver.com"}
