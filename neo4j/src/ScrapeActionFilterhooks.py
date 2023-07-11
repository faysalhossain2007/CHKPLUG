import requests
from bs4 import BeautifulSoup

# url="https://codex.wordpress.org/Plugin_API/Filter_Reference"

# # Make a GET request to fetch the raw HTML content
# html_content = requests.get(url).text

# # Parse the html content
# soup = BeautifulSoup(html_content, "lxml")

# for link in soup.find_all("a"):
# 	if "codex.wordpress.org/Plugin_API/Filter_Reference/" in link.get("href"):
# 	    print(link.text)
# 	    print(link.get("href"))

# https://stackoverflow.com/questions/19859282/check-if-a-string-contains-a-number
def hasNumbers(inputString):
    return any(char.isdigit() for char in inputString)


url = "https://developer.wordpress.org/reference/classes/"

# Make a GET request to fetch the raw HTML content
html_content = requests.get(url).text

# Parse the html content
soup = BeautifulSoup(html_content, "lxml")

for link in soup.find_all("a"):
    if (
        "developer.wordpress.org/reference/classes/" in link.get("href")
        and " " not in link.text
        and not hasNumbers(link.text)
    ):
        # print(link.text)
        print(link.get("href"))

for i in range(2, 13):
    url = "https://developer.wordpress.org/reference/classes/page/" + str(i) + "/"
    html_content = requests.get(url).text

    # Parse the html content
    soup = BeautifulSoup(html_content, "lxml")
    for link in soup.find_all("a"):
        if (
            "developer.wordpress.org/reference/classes/" in link.get("href")
            and " " not in link.text
            and not hasNumbers(link.text)
        ):
            # print(link.text)
            print(link.get("href"))
