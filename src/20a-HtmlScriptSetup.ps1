# ===== HTML Body Structure & Script Setup =====
$htmlPage += @'

<!-- html2canvas for screenshot capture -->
<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js" integrity="sha384-ZZ1pncU3bQe8y31yfZdMFdSpttDoPmOZg2wguVK9almUodir1PghgT0eY7Mrty8H" crossorigin="anonymous"></script>
<!-- MSAL.js v2 for Microsoft Entra ID authentication (Authorization Code + PKCE) -->
<script nonce="__CSP_NONCE__">
const entraTenant = '__ENTRA_TENANT_ID__';
const acsApiKey = '__ACS_API_KEY__';
const acsIssueUrl = '__ACS_ISSUE_URL__';
const appVersion = '__APP_VERSION__';
const msalSources = [
  '/assets/msal-browser.min.js',
  'https://alcdn.msauth.net/browser/2.38.3/js/msal-browser.min.js',
  'https://cdn.jsdelivr.net/npm/@azure/msal-browser@2.38.3/dist/msal-browser.min.js'
];
let msalLoadPromise = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = false;
    s.onload = () => resolve(true);
    s.onerror = () => reject(new Error('Failed to load ' + src));
    document.head.appendChild(s);
  });
}

async function ensureMsalLoaded() {
  if (window.msal) return true;
  if (msalLoadPromise) return msalLoadPromise;

  msalLoadPromise = (async () => {
    const errors = [];
    for (const src of msalSources) {
      try {
        await loadScript(src);
        if (window.msal) return true;
      } catch (e) {
        errors.push(e.message || String(e));
      }
    }
    throw new Error(errors.join(' | '));
  })();

  return msalLoadPromise;
}
</script>
<script nonce="__CSP_NONCE__">
(function() {
  try {
    var local = localStorage.getItem('acsTheme');
    var support = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (local === 'dark' || (!local && support)) {
      document.documentElement.classList.add('dark');
    }
  } catch (e) {}
})();
</script>
</head>

<body class="section-fade-enabled">

<div class="container">

<div class="top-bar">
  <div id="languageDropdown" class="language-dropdown hide-on-screenshot engage-top-item">
    <button id="languageSelectBtn" type="button" class="language-trigger" onclick="toggleLanguageMenu()" aria-haspopup="listbox" aria-expanded="false"></button>
    <div id="languageSelectMenu" class="language-menu" role="listbox"></div>
  </div>
  <button id="themeToggleBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="toggleTheme()">Dark mode</button>
  <button id="copyLinkBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="copyShareLink()">Copy link</button>
  <button id="screenshotBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="screenshotPage()">Copy page screenshot</button>
  <button id="downloadBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="downloadReport()" disabled>Download JSON</button>
  <button id="reportIssueBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="reportIssue()" style="display:none;" title="Report an issue (includes the domain name)">Report issue</button>
  <button id="msSignInBtn" type="button" class="hide-on-screenshot ms-sign-in-btn engage-top-item" onclick="msSignIn()">Sign in with Microsoft</button>
  <span id="msAuthStatus" class="ms-auth-status hide-on-screenshot engage-top-item" style="display:none;"></span>
  <button id="msSignOutBtn" type="button" class="hide-on-screenshot engage-top-item" onclick="msSignOut()" style="display:none;">Sign out</button>
</div>

<div class="search-box engage-section">
  <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAlgAAAE7CAYAAAAB7v+1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAACzzSURBVHhe7d15dFVVnujx+s+/3vLN9Htd3a7Vq1bZr/v1872uwXLEseiqrirEARzBGUUFlSEECAHFiAooCAEBCUOIiooiiiAKThXnaKkMQkiYcnMz3YyEIXD22/tyYiH+gAznnrP3ud/vWp/l6lZyz7mVs/ePc29ufkL2VJTfePry3Jb+y3Nb8wEAPVc8rmVo8bi2s/zllYiyrWXjms9ePr5tRklua1nJuDYFAAhQbmu7/ueGkrGtI1aMauvjL71EFNf036yGlOS2lf5oMQAAZE7uvkXmL7b+UkxEcWlZTmvf5bmtieW5bQoAEI3isW0rzdsy/KWZiFytaKI6rWTsvgLpQgcARKE1Yf7S6y/TRORaR9+83lb644sbABC1ZbktOf5yTUSulB6uxraWSRc1AMAODFlEDvX9cDVWX8AAAKsV57QN8ZdvIrI5fcFuOP4CBgDYa+nYtn7+Ek5ENmb+JiRdvAAAexWPbaswP5TkL+VEZFNFo9r6FI9tTWn6YgUAOKbAX86JyKaKx7aUCBcsAMAFOS3t/JodIstK373KMRcoAMBVy3JaC/1lnYhsqHhMa4F0sQIAHDKmpZ33YhFZkrkYi3NaEuLFCgBwy+iWof7yTkRRZn7lgniRAgBctMZf3okoypbktOToIcu8dg8AcF5Lwl/eiSjKlo1uKVk2Rl+UAIBYKBrReLq/xBNRVC0d01ImXaAAADctHdXEJ7sTRd2y0S3t0gUKAHDT0lHN/H5CoqiTLk4AgLsYsIgsSLo4AQDuYsAisqBlo/UFCQCIDQYsIgtaai5GAEB8MGARRd/S0S36ggQAxAYDFlH0iRcnAMBdDFhE0SdenAAAdzFgEUXf0lHmYgQAxAcDFlHkyRcnAMBdDFhEkbdEX4wAgPgoYsAiij7p4gQAuIsBi8iCpIsTAOAuBiwiC1oyUl+QAIDYKHqQAYso8qSLEwDgLgYsIgtaMrJZX5AAgLgoerCRAYso6qSLEwDgLgYsIgtarC9GAEB8MGARWdDiB/UFCQCIDQYsIguSLk4AgLsYsIgsSLo4AQDuYsAisiDp4gQAuIsBi8iCpIsTAOAuBiwiCyp6QF+MAID4GMGARRR54sUJAHAXAxZR9IkXJwDAXQxYRNEnXpwAAHcxYBFFX9H9+mIEAMQHAxZR9IkXJwDAXQxYRNEnXpwAAHcxYBFF36L7mxQAID4WMmARRZ90cQIA3MWARWRBi0boCxIAEBsMWEQWJF2cAAB3MWARWZB0cQIA3MWARWRB0sUJAHAXAxaRBT2rL0YAQHwwYBFZ0LPD9QUJAIiNhfcyYBFFnnRxAgDcxYBFZEHSxQkAcBcDFpEFSRcnAMBdDFhEFiRdnAAAdzFgEVnQs/fpCxIAEBsMWEQWtNBcjACA+GDAIoq+hfc16gsSABAbDFhE0SdenAAAdzFgEUWfeHECANzFgEUUffpCNBcjACA+GLCIok64MAEAbmPAIoq6BfpiBADEx3wGLKLoky5OAIC7GLCILEi6OAEA7mLAIrKgBffoCxIAEBvzhzFgEUWedHECANzFgEVkQQvuSekLEgAQF/OH1TNgEUWddHECANzFgEVkQfPNxQgAiA8GLKLomz/MXIwAgPhgwCKKPPniBAC4iwGLKPLkixMA4C4GLKLIky9OAIC7GLCIIk++OAEA7mLAIoq8Z+5OKQBAfMwdyoBFFHnSxQkAcBcDFpEFSRcnAMBdDFhEFiRdnAAAdzFgEVnQM3fpCxIAEBsMWEQWJF2cAAB3MWARWZB0cQIA3MWARWRB8+5qUACA+GDAIrIg6eIEALiLAYvIguYN1RckACA2GLCILEi6OAEA7mLAIrIg6eIEALiLAYvIgqSLEwDgLgYsIguam74YAQDxwYBFFHlz79QXIwAgPm5nwCKKPPHiBAC4iwGLKPrEixMA4C4GLKLoEy9OAIC7GLCIok+8OAEA7mLAIoq+uXfoixEAEB8MWETRV6gvRtivaExKvTSj6QeeuUf+b/FDS8f/+LmT/jscZb6vOp+n9cUt6t0XW79n/m/z/zfPqfRnYYfZDFhE0Vd4R72+IGGT5x5J6c2sRX31/j5VsWm/2rnlwAmZf1/2blv6v1/xWKP49bKJeQ4+XNWafu6k5+tY277arz5/p02981xL+jmXvl62eGnG0edty2ft4nMl6Xz+1i1uVgsfMBu7/LURPgYsIguSLk6Ez2xwn6xtS29a0mbWVVu/aE8PDEfvMMiPFTevFTapT99qU+Vf9+65M8NFNg0LRWMa0t9zvX3eDDPom6/FkG8HBiwiC5IuToSneFIqfRdA2rR6y2x4ZhOVHjcOzGbelTtV3WWGhfdXtsR20DLnZc7vVHdHe8p8P2fTgG8jBiwiCyq8XV+QCF3R6AZV+nqruEEF6fth4X49LAjH4aKl4zI3lB7L3E1cv6xZPAZXmTt0QdyxOpXO77tnhsnHgcxiwCKyIOniRGaZOy+9fSmwu8zLX8X5KfF4XPLanKZQBoRjmbtkrg+oZtAxL6NK55dJ337cnh6IpWNC5jBgEVnQHH0xIjxrFzdn7KWZUzGDyepnmsTjcsHGF1vE8wqDeW/bC3owlo7Ldkv0gGMGHem8wmC+716a7uZz5yoGLCILki5OZIb5KS1pAwrbmoVuDVnzIrr7cjwzGK+c6dagYAabsO/4SVx87lzGgEVkQdLFieDZMlx1cmnICuP9Vl1lBoXnpqTE47TNsvyUFcNVJ4as8DBgEVnQnNv0BYmMWlvULG44UVs9Tw9ZwvHa5L2Xo3tZ8ETM0JIesoTjtcWCEQ3plzWl449Sxbf71QtT9ZAlHDOCM/tWBiyiyJMuTgTnpWmN6U1F2myiZgYF8/4c6bhtYAZA6bhtsPnTdjXvbvm4bVC20Z67fsez/bmLAwYsIguac1udviCRCYtG1attX5m7CGbAstNX77eJxx61ZRMb/MHUXh+/2Soee9SO3vWTj9kWpa+3iMeOYMy+tYYBiyjqpIsTwTAbsLS52OatZealQvkcomIGP+lYbbNqjnm5Sz6HKJih3vbBtNPKp+x67uKEAYvIgmabixGBK5nSoCr1JuICc5dt7t3yeUThVT20SMdpo28/2ieeQ1Q+WNUiHqeNbHvuYoUBiyj6Zt9qLkYE7fO328RNxVbmLpZ0HlEwG690jLZ6dXajeB5hMy+r7vhWPkZb2fLcxQ8DFlHkyRcneqPkYXfuXnXa9mW7mnuXfD5hMhuudHw2S9+JEc4lbJ+uaxWPz2Zff2jHcxc/DFhEkSdfnOgN894raTOx3RsLor+LZd57JR2b7V6clhLPJyxmOHbt7lWnxbkN4jmhNxiwiCJPvjjRG+bjD6SNxHbmR/ul8wnL/OH14nG54M+rW8RzCot5w7h0XC54u6RZPCcbLZ7VqJbMbRItfDTaIfuHGLCIIk++ONFT5k6GtIm4wNwBMUOOdF5hMHfQpONygXmJVTqnsJgBTzouF0T9MqEZjMyA9NLb+9Sqj9rV2q0H095rOKLeb1a9sqH68Pdfb+XGfWrFa23px3pmXKbv2jFgEUXe7Fv0xYjAmM8gkjYRV6ye2yieVxhcfA/RsV4wdzCE8wqD+dR26ZhcMf8+PdgL5xWkhQUp9dwLrelBas2mg+qtyg5xKAqTGbxWlx1IH1Px4pajg5dw7N02hAGLKPLEixM95tpPwB3PDIjSeYXB1ZdWO71Z1CSeV6YtHuveD1UcLxPD6fz8lCrRA5UZYN6pPqze0wONC9bv6kjfSVumB665D/Rw8GTAIoq+p/XFiOC4+kbjTp+93SaeV6YtHOnu+686ffBqi3humbbiCXdflu5khlPp3Lpj3rgGVVzSkh5O3q5yZ6A6lXWVHemXF5csbFZz7qkXz/14sxiwiKJPujjRM4VD68TNwyXm98RJ55Zpyx38aIvjfbExmuH0dYffu9app8OpGaqee6VVvbWrQ72rh5FssPovB9KD5MmGLQYsIgt6+mZ9QSIQRealms16w3CcdG6Z9vKTjeKxuGTr53o4Fc4t095e3iwej0s+XtMqnptkzrB6Vby8JT1oSANItthQd0St+my/WlzY9KPniAGLyIKOvzDRc+mXaoTNwzXSuWVa+i6McCwuiWrAMnd/pONxSfqlaeHcjmUGiVc+2a/erj2iNjYpHGPd3sPqxY371IKCVPq5YsAisqDjFzH0HANWz214wf27MFENWObuj3Q8LvnyPXnAKnygXq14a59aqweIDXqQwKmtqehQKz/ev8Bf4okoqp6+uVYvZAjCiifi8hKhfH6Z9OaiOLxEuE88t0yLw3B6dMD66znNy61XL7+/T62vPSIOETi1d5q8ircbvREblDrNX+6JKMyOXdTQO0sn1Iubh0u2f23uwsjnl0mvzXV/wPrmIwasnjr6Hqyjg9VLZrBqOKIHBDMkoLfebvISDFpEEfT0EL1IIxBFOe4PWOkhQTi3TFvxuPt3/z5br4cE4dwy7fX57g+nG15vTb+/ShoQEAw9aKXeaVT5GxvV6f7yT0SZTFqw0TOFd9Ye/RwsYQNxRVRDQhyG0w9eaRbPLdOWT3Z3ON3+3QH1WXWH3vzNAIAwrNeD1noGLaLMJy3Y6DnzXhJpI3GFeblJOq8wmPcwScfkCnMnSTqvTHNxsK/Ysl99uUcPVo2eOAQg8/SglXi7UfX3twIiCrpZeoFGcFx/P4x5qU46rzB85PhPwy3KqRfPKwwuDfabKw6q9+qP6A3ebPKI2lvN3pq1LepMf0sgoqCSFmv0nMvvJTJ3QebcKZ9XGFx+L9GWz/eJ5xQWFwZ783LgR8nD6i2zqcMq65q8dj1oFfBGeKIAmzVYL9AI1HdftosbjO2+2NAqnk9Y5t3j/y5H4dhs9+FrLeI5hWXBA3XicdmizLwcmPLEzR028SrWNnn9/O2BiHqTtFijd959yc2XCV+ZlRLPJ0yfrHXzZcLiyQ3i+YTJDMjSsUVpS/lB9W79EbVOb95wSLO35vU21cffJoioJ0kLNXpn0Rj3fiLO3HWTziVsLr7Ean7yUjqXsJkBWTq+qHy565Ba1+jJGzgc4CXebFR9/a2CiLqbtFCj98ymK206tlq3pEk8jyh8U+rWTxPacOevkw3P3Y6tB1Rp8rBaqzdpuE8PWfn+dkFE3UlapNF75j0xrryfyNy9mnOHfB5RMC+3ScdpI/PTe9I5RCXqO4DmJcF3Go6IGzVc5m3gJUOibjbrJr0wIyNceS9W+g6McPxRcuG9WGaAXjKuXjz+KEV19/SLPR3qzUZPvak3ZMSRl3idN8ATdb2ZekFGZsy+vVZt+sTul7s+1oOMdOxRm39/nfU/jbm+uEk89qiF/dyVbz2gPqg9rNboTRjx92azV+BvH0R0smbeVKMXZWTK4nF1avtf7BwUzGc3zR1mNmX52KP2wmMNase3dj535if2Zt8uH7cNwnruvtt+IP2LmaWNGDHW7K15hV+1Q3TypMUZwbLtp7sMM/Q9O7pOPF6brF1i34ePflPaZvVg2inTz93W7QfV2pSn3tAbLrKRV8aQRXSSpIUZwVv9jD1DlrmzYe5wSMdpo3eebxLPIwrmrp8Lg2mnTD1331YwXEGp15u8ijcb1Rn+dkJExzbzRr0QIxRmyNrxTbQveZk7VyVT6sXjs5l5v5N0PmEyd67Sw5VwfDYLerj/uuKQeqPR05ur2WCR7VabN783qrP8LYWIOpMWZGTOS9MbIntPlnnDvYsDQqcoB9Qv321Vc++uFY/LBavmpAL5vvty5yG9oZpNFTiWl1rNh5IS/bCn9OKLcM0fUavK9IZdoTessJS+0aIK9YAgHY9LisbVqa9L28RzzAQz0JmX2Z6+TT4el/T2++7TPR3Cxgoc9VqT1/5ao+rvby1EJC3ECMdbxU3puwrSZhYUc9fq+ccaxMd3lRl2Nr7YlB5+pHMOylcftKUHOukYXLZ2caP6rmyfeM4n8okerl5Lb6LAya1qVEP87YUou5MWYITH3FUyd0iCHrTMm7HfeLYxFndeTsTckXlvZXPgg5YZrFbOSomPGRfm+6KrgxbDFbprFR9ISqQHrBv0govIFd5Vq95Y2Kg+f6fnL+GYQePTt1rUypl6OBAeI67mD69NDwu9eenQDLgfr21J/wCA9BhxZr5fzEvI0pBftvOQuSMRG8/tPaRW1nviv0NwXm302lfVe2f72wxRdiYtuIiWGbbMG7rNy2DmPTMnustgBgrz781dnBenNYhfK9s8O6ouPWyZ58Q8Nye6M2j+nWGe42wcqk7k+akN33/v/fmr/XqjNJul25btPqiGrtijznlsq/rJ2G/TzsjbpO5duTf976Q/gwCkvNQr/HQhZXNP3ZDUCysA/NX8eSn1Sv0ReeN0yIwvmtLDVOdgdTzz7574NCX+WQQg5VXoIYvPyaLsTFpcAWSvwqkNaqUervTG6KwVtYfVrct3iUOVZPY3LeLXQRC8zfqffOI7ZV9P6gUVAIzZk+vVi8kjaqXeGF1VuLlN/eaYlwO74l+mbFEl1R3i10PvvZzyyooq1Wn+tkOUHT15vV5YAWS9WQ/WqhW73R0yXqr31Mg3qsUBqity1iXFr4ugeGv8bYcoO5IWWgDZp2TTQfWy3ghd9KIerm7uxkuCkr/P26SWV3eIXx+Byfe3HqL4Jy20ALLLonVt6iW9Abqqt8NVpzHrkuLXR3Be5FfqULYkLbYAskfhtAb1Yv0RcTN0wfBVCXFY6onOu1jS4yAgR3+ykDe9U/yTFlwA2WHmvbXq+d0d5q6Ck+4LcLjqNHpdUnwsBCjlrfS3IKL4NuO6pAKQnZaV7Zc3QAdkYrgyzF2s4mp3h05XrGj0RvjbEFE8kxZdAPE3/9UWvcmZjc49EzbWisNRUMxdLOlxESSv/Xl+nQ7FOWnhBRBvs6c1qBfqjwibnv0WVB5I32WSBqOgmK+/rLpDfHwEiPdjUZyTFl8A8fXkLTVqeWWHeiGlnPTHeeXiUBS0UeuS4uMjaN4ifzsiilczrtWLLoCsMf/1VvW83thcNPH9OnEYyoRfP7ZVldR54nEgYLxUSHFMWoABxNPMB2rVc3VH5E3Ocgt3HVR/l+GXBo83ubRBPBYErMEr87ckovgkLcIA4mlx2X71nN7QXHTlwgpxCMokcxdreZ0nHg+CVVLPTxVSzJp+bbUCEH9zFjSKG5sLJpU2iANQGMxjS8eEoHntK2pUH39rInI/aSEGEC8zbk6qpbs6VIneyFxTXOepXz22VRx+wmAe2xyDdGwImlfib01E7jd9kF6AAcTa/Ddbhc3MDdO+bhEHnzDllzaIx4bgPcfvKqS4JC3GAOJjZn6dKq47opbrzctFg5bsFIeeMJm7WMvqPPH4EKzilLe5qFKd5m9RRO4mLcgA4uPZsv160zIbl3vmVBwQB54oTCxtEI8RwVvGG94pDkkLMoB4mFVQL25grrh/XVIcdqJg7mItrfPE40TQvAR3scj5pulFGEA8LSzbr5bpDctFi2oOq5+G/LlXp1LwZbN4rAjeEu5iketNG6gXYgCx82RurbhxuSIvwo9mOJHfzysXjxUZ0OBV+NsUkZtJCzMA9z2zsU0t1RuVq66I4INFu2Lq1y3i8SID6lR/f6sici9pYQbgthn316gldUfkTcsBhbsOisONDW57ea94zMgAfoUOuZy0OANwm7l7tURvUK4avbFWHG5s8L+mbBGPGZlRxF0scjVpcQbgLnP3qqjuiFqsNydXXfL0dnG4scXcPYfE40YGcBeLXG3aNXpRBhAb8za2yRuVIxbUHBaHGptIx43M4S4WOdkTekEGEB8Lqw6rIrMpOarAgl+NczK/eGyreNzInEX8jkJysSeuSehFGUAczCxsEDcol4y0+P1Xxn3rkuJxI3P0gNVe1KhO97ctIjeSFmkAbpr3abvejMyG5K5rl+8SBxsb/G3eJjU30SEeNzJrYYM31N+2iNxIWqQBuGfaXUm1sO6IuDm55I+Wfv6VMeb9OvGYkXnPprxSf9sicqMnrtaLMwDnzSpu0puQ2Yjcdu6MbeJwE7WJn8fj+XVZUaM6w9+6iOxPWqgBuGfepgNqod6EXPePU7aIA05ULn56u3pie7t4rAjXggaV729dRPb3uF6YAbhtek6NuCG5SBpyomAGvVHv14nHiIjw+wnJpaTFGoBbZq1qMX+7jwVp2Anb4Jf3qtlVHeLxIVrz672z/e2LyO6kxRqAW+ZVHBI3IxdJA09YLpq1XU3dsk88Llgi5RX62xeR3T1+lV6gAThrWk6Nmq83nriQBp9M+595m9TI9+rUvDpPPCZYpJ6XCcmRpAUbgDueKm6SNyJHnRPyTxFesXinerqqQzwW2GkuP01ILvT4VVV6kQbgqtl/3qee0ZtOXJiBRxqEMqHvrO1qTvKweByw19x6NcTfwojsTVqwAbhjbuKImqc3nbi45dWEOAwF7edTtqgndx8SjwG281b6WxiRvT2mF2gAbpr2UK2w+bht+IZwfhehGeSkx4cD6r2Uv4UR2dtjV+qFGoCTnny5Sc3VG06c5H/dIg5EQbtPD3LS48MNs2vUWf42RmRn0qINwA1Pf7Ff3HxcNmP3IXEgCto96xmwXFZY743wtzEiO5MWbQBumJM4ogrNZhMzZ4fwk4S/W1ghPjZcwfuwyPKkRRuA/Z54qFbYdOJh0At7xKEoaE9WdYiPDwfwPiyyPWnhBmC/6S83qTl6o4mj0R+nxIEoaOZxpMeHG3gfFlnd1AFVCoB7nny3Tc2u15tMDE3f2yEOREG7sniX+Phww9O13iB/KyOyL2nhBmC/p77cL246cfHHED5w9G/yNqlZtZ74+LDfrDqV429lRPYlLdwA7Ddzz2H1tN5k4mrkR+G8TJj7RbP4+LDfrHqvxN/KiOxLWrgBWO6OanHDiZNpIb1MeNOrCfHxYT89YJX5WxmRfU29Qi/WAJzy2ORavbmYDSbe/hDCy4Q/e3iLeqrWEx8flqvjJwnJ4qTFG4Ddnng2JW84MRPWy4STNu8THx/2m12j+vjbGZFdSYs3ALtNX9uqZurNJe6eCOllwiGrq8XHhwNqvH7+dkZkV49esVcBcMuMj/epp/Tmkg2uej7zHzr6qxnbxMeGA+q8of52RmRX0uINwG4zvjsobzYxlPuXcH7586Tv2sXHh+UavBn+dkZkV4/21ws2AKdM39mhntSbS7a4aG65OBQF6ZY3k+Jjw24zGrxF/nZGZFfS4g3Abk/WHBE3m7i678MGcSgK0r88tlVNr/XEx4fNvDX+dkZkV9LiDcBuM/TGkk2m6cHnf+sBSBqMgjT6i2bx8WEzb4O/nRHZlbR4A7DYdVXCJhN/5iU8aSgK0uULK8THhsXqvFJ/OyOyqwK9YANwx6Ojk2q63liyzaN7O1SfvE3iYBSkSeUHxMeHnabVexX+dkZkVwV/0os2AGc8OiqpNxWzsWSfASF8ZMONq6vFx4atGLDI0qQFHIC9pj5aK2wy2SG//IA4FAXJ3CV7vNYTHx828tr97YzIrqQFHIC9Hp1ep57QG0u2uiKEu1jDPmwQHxt28rczIruSFnAA9np0Zr24yWSLiSHcxbpwbrn42LDTxEp1mr+lEdmTtIADsNfUpY3qcb2pZLMbVleLg1GQcjfvEx8b9nm0UZ3hb2lE9lTwR71oA3AGA5ZSU/Z2qP+e4Z8ovPqlveJjwz4MWGRlj+gFG4A7CmbWq8f0ppLtbsrw52KZAe5hPchJjw278BIhWZm0gAOw2LQ6NVVvKtnuoRDuYt2ohzjpsWEXfzsjsqtH/rhHL9oAXFHwaI24yWQjMwBJg1FQzAA3sfKg+NiwBR/TQJYmLeAALDaqWj2qNxYoNXlvh/qnDP+Owj89v0d8bNihgA8aJVt75A96wQbgjpHVelMxGwuMOz9sEAejIN3/lxbxsRG9RxiwyNbEBRyAvQbuVQV1enNB2pQaT50/t1wcjILyf2dsSz+O9PiIGr/smSxtil6wAbjlEb2x4K/u/6pFHIyCdNu7deJjI2K13gZ/OyOyK2nxBmC55BE1RW8u+Ks/ZPhX6Pw384b3PR3iYyNK3hp/OyOyK3HxBmC3Sjb6443dfiA9BEnDUVDMECc9NqLzSJ23yN/OiOxqyr/rBQOAUx7aelA9rDcX/NB1Gf7YBmPkpn3iYyMq3gx/OyOyK2nxBmC3hz7apx7Smwt+aMKeDvWPGf7YhnPnlqtJNZ74+Ajf5KQ31N/OiOxqyr/v1gs2AJc8vLJJ3Gyg1G0fZP5jG8xjSI+N8OUnvbP97YzIrqTFG4DdHlpQrybrzQU/ll/jqXMy/LEN/zVvkxq/p0N8fIQrv0b18bczIrt6WC/WANzyUH5S3Gxw1L0hfGzDgFcS4mMjRLVeyt/KiOzr4d/rBRuAW67eoybpDQYn9vsMf2yDcY8e5KTHRlj4kFGyOHHxBmC9/MoOla83GchGbj+g/kuGP7bh7x/eokZXHBQfH5k3kY9oIJuTFm4A9ssv2y9uOvirgSF8bMMvZm1XeTWe+PjIsBqV429lRPYlLdwA7DdpfYuaWKv/Fo8TGru7Q/18amY/tsHo/0pCfHxk1oSk6u9vZUT2JS3cAOw3uTglbjr4oaGfN4tDUdDu+KRJfHxkTn6dOtPfyojs66Hf7VYA3DN5YlLl6U0Gp3bZsl3iUBQk836vkTsOio+P4E2o4ScIyfKkhRuAGybsOSxuPvihB7YdEIeioP3rzO1qfNITjwFB81b62xiRnT30u116oQbgorxP9qkJerPBqV29JvNveDf+9EpCfHwEaxy/IodsT1q0Abghv6hBjdebDU5t9O4O9XcPbxGHoqDdXJoSjwHByalWZ/jbGJGdPfRveqEG4KTJw6vEzQeywSH8nkLjP+dtUsO3tIvHgCB4Ff4WRmRv0qINwB3jKzrUOL3p4NTGJj31/2ZuF4eioP3z9G3pu2bScaB3cmv5gFFyIGnBBuCOCe+3iZsQZHd+mfnfU9jp13PL1Ziqw+JxoBdq1BB/CyOyt8l6gQbgrryiBv03evO3enTVJSF8bEOnC4t2qpykJx4Heob3X5ET6QU6dfyCDcAdk4ZXiZsQTmx4SB/b0Ony5/aIx4Ge4P1X5EiTf7urdHI/vVADcNa4LQfVWL35oOsGhPSxDZ3+/ZWEeBy9NXJ3h7p70z41JumJ/z5+vAJ/+yKyu4d+u7tQWrABuCPv+ZSwEeFkzGDy05A+tqHTwLdrxWPprlFVh9UNHzSocxZU/OgxzCA3Ykd8B+5xNeosf/sisrv8fpVDpQUbgDsm3blXjUkcUTk1Ct1w/fvhfGzDsW76c0o8lq4YXe2lj/lnXfgF1kM+bhK/htOSXpm/dRHZX/7llWdN7rdTL9IAXJb7WbsaozchdN0oPbCcFdLHNhzrls+axeM5mcF6YPqn6dvEr3ci5s9IX8tVo6pVjr91EbnRpH47yzQFwF15z9SJmxJO7ray8D62odN/ytuk7vhLm3g8xzP/3S8Ly8Wvcyrmce7ZdkD8ui4aVaP6+NsWkRvl/7ZyxKTf6kUagLsG7FJjdh9Wo/VGhO7puzS8j23o9LcPb1HD9PAjHY9x1+Z2dX7RTvHPdscv9HA2stoTH8MpSW+Nv2URudPECypP0wt0+48WbABOyX2nRd6ccFLDKw+l7/ZIA0ommce87v0G9eDevw7GZrC69Lk94n/fU1evr/3B+bpID4mD/C2LyK3yL6/MlxZsAO7Im5o0L6OgBwZurBOHkzhIv1RYflA8bxeMrPHaJ1aq0/ztisit0nexLt+5WVq0AbhjzI5D4iaFk3uw2ku/nCYNKHFw9oIK8bxdMJrfPUiul39Z5dnSgg3AHeOeS+m/8Zu/9aO77tzcLg4ncXHNxjrxvG2nhyw++4rcb9LlO2doCoCjrtilRlZ2qAf1xoTu+/2qanE4iYP/mLdJ3V1+UDxvWz1Q4630tyci95t42c5F+XqhBuCmseuaxc0KpzZi72H1D134IE9X/XpBhXje1kqq/v7WRBSPGLIAd028Y4+6P3FE/+3f3AFAd934WbM4nMTFwPcbxPO2Dp/cTnFt4uU7Z0iLNwD7mbtY4qaFLrko4I9KsIl5qXBY5SHxvG0ygrtXFOfyL63spwethLSAA7BX512s+/VGhe67b+9hdWY3fzWNS84p2imetzW4e0XZUH7fyj4TL9tZkn+ZXrgBOCNnbbO8eaFLbv12nzicxMWgP6fE87YBd68oq8rvV3nGxEt3FuhhKyUt5gDskuffxRphNiz0SP/1teJwEgfmpcK7Kg+J5x2l4dy9omzNfCjpePPS4aUVetiq2DDxskoFwE6j1zar4WbTQo/9ckGFOKDEwW+KdornHKV7uXtF9MPyL6w8Pf/Syr5w04RLKgflXVpRJm3S6ImKlXmXVQ6Vnusw5T5VM2B40jsgbWTomqGVh9T/eHiLOKDEwbUfN4nnHYX7uHtFRHHM3J3krmTv6CF1s/mtCP5TakV60xpxn9m80GOD9BAiDSdxYIbHu3Z1iOcdtmF8ajsRxTVz12PipXpYQLfowao9/bK5HlL9p9KqzJ0BaUND1/WL8ae8n7d0l3jOYbq3xpvhf7sSEcUzaYDAieVdUlGa37fyTP/pszI9YJ19b3oTQ29cEOPPxxr4cZN4zqFIeokRjep0/9uViCieSUMEfszctcq7uDLHf9qs775ab5G4uaHLhlV76uyineKA4rq/eXiLGrqrQzzvjKtWQ/xvUyKi+CYNE/ghF+5aHd+wGtXnnqSXuEdvaOi5u/YeVv+nsFwcUlxn7tBJ55xJw2q8Df63KBFRvMszAwREExy7a3V8dye9oXrQMm8mRi/cVnlI/Symn/R+a/lB8Zwzw2vX/+SN7USUHeVdoocJCNy7ayWlh6yyH2906C4ziJiX1aQhxWX91iTF882Eu2u9Av/bkogo/snDRfaacInbd62O784qdaYestrvTuoNDr0y5LsDsRuyfrVop3iugav2SgdXKit/6paIKCNJQ0b2isddq+MbWq2GiJseuu2W7Qdj9XJhGAPWXUkvpb8Hz/C/HYmIsiN50MguEy6pSMXprpWU3uQW3ZXe7NBbd+w5rH6pBxNpYHGNOQ/pHIOkhyx+HQ4RZV/SwJFVLq5Yk9+3so//dMQ28/KMHrI2Sxsguu/OhKcuXpkQhxaX/NvaWvH8gnI3HyhKRNnahIsrVTYaf3FFakLfyqz6PB7zfqyhSa99qN74EIw/bKgTBxdX3FJxSDyvINzJ+66IKJuTho/4y467VlK3V6shd5rND4G55osW1cfBN7//bn2teD7B4H1XRJTl6WHDDBxZYfzFO1IT+pZn/adI681vkbwpoqdu2dmhzl+xVxxkbJTZ4SqN910RUXYnDSIxlbV3rY7PvGxzR9Iru0NvhAjWwK/a1D9Y/FOGv1i0U139RYt47IHhfVdERHrAukgPHzE2/iLuWkkNblSn3570NosbJHrtio+a1D9b9Ct2zN21G747IB5rkPT3VIn/LUZElN1JQ0mMcNfqJJn3yOgNseL29MaITLjqixb1m5I94tCTaf8hb5O69I2kGlxxSDy24HlreFM7EZGfMJQ4b/xFOxLctepaQ6rUmbclvdRteoNE5ty857Dq/1FTetj66dSt4kAUhJ/P3K4uWJlIP5Z5TOlYMuHWpFdm7or631ZERDQ+PZDEyqL8CytZ6LvR7UnvbD1ktUsbJzLDDD8Dv9mn+q2vVZe8kVT/umhnejiShqaTMX/molXVasCnzWrwzg7xsTLPqxhSo7hTTER0bMKA4qRxF+1IjO+7vZ9/WtTNbkt4/W6t9tpvrVYK0bpxxyF1zdf71J9Km9Rv36pVV37Rkv6/jzVk92Hxz4bPSw3h4xiIiH7c+L56QHHdhdy1CiK9UQ65RW+aQNd47UP2qrP8bx8iIjo2cWBxxLgLuWsVdEMS3lB5MwWOpYerhMe1R0R0oqTBxQnctcpY5k7WzXoDvVlvpMCPeSnuXBERnaLxfXfogcUd4y4s565VCJm7E4PNXQq9oQKdBie8Cv1P3nNFRHSqxpmhxRG5F+7grlWImbsUesgyb2IWN1tkF/29UMZPCxIRdbFxF+rhxXYXlFeMPZ+7VlFkPifrpoRXMTi9wSJrJbwNgyv5nCsioi4nDjRWKS+YeEElnw4dYUOq1Rk3VXtlN+mNFlko6ZXwCe1ERN1MHmoscEH55nF9t53tHyZFnLl7cVPCKxU3YMTWjdVeof8tQERE3UkcbiLHXStbuzHpFdyY3ngRZzdUe6kb93qD/P/ZiYiou8kDTkS4a+VENya8fukNWNiYEQde2XVV6kz/f24iIupJ4y4wg40FzueulUuZnya7PuGV3qA3ZMSJV8j7rYiIAihXDzdRGnt++eYx53HXytWuT3oF8kYNl1xf7aWu4yVBIqLgkoaesOjhirtWMejahNfvOr1BX5/eqOEa/b8dLwkSEQWdNPhk2tgLdpRx1ypeDapWZ+iNes116Q0brrg26RXwkiARUQaSBqBMGXt+ebv+Z47/0BTDrqtS/a9LeAlpM4dFEt4G7loREWWw3PP18BOO0txzKlnQsyBzR8TcGRlU7bVfqzdzWEQPvwN5rxURUeYTBqFAjT2vvD33PO5aZWPmDokestaIGz3Cd/TlQH7dDRFRGI09v9y8dJcppbnnbOWuVZY3sEr1H5TwEoP0Jo/wDeTlQCKi8BOGol7LOW97e85527hrRd9nXjYcWOWNYNAKk1dmhlv/fwIiIgozaUDqJe5a0QnrHLQGmvcC6SEAmcBgRUQUeWPP00NRAHLO5a4VdT0zaF2tB62r9aB1jR4K0HtXM1gREdmTHo7Kjh+Wuu3c8g3ctaKepoeDIXrQqjh+YEAXJbwNV1Wrvv7TSURENqSHowJxaOqKc7encs4tH+J/KaJepYcFM2htuFoPDTi5q6q99quSXgmDFRGRpY3qW9nHvLwnDlAnoQerNebP+l+GKLAGVaszrqxSOVdXe5ul4SKr6QHUDKL9+bgFIiL7M3ehcszQ1BXctaIQ04PWmVclvBlXVnmJqxJKZSdv84Aqb8Q1NYq/0BARudboc7cNHXPO9nY9PJm7UyeyZtQvuWtF0WReDtPDxqLsGLa8zVqBGTD90yciIlczw1POOTsKx5xbXtE5VPlD15pRv9nez//PiCLPDB5X7PWGDkh4K69MeKkr9VDitCqvQp/LogF7vUHcqSIiIiIr6r9XnXVFlcq5ospbc0XCax+ghxab6eNM6OMsMUNi/2p1hn8aRERERPamh5a+5m7QgCqVb+5y6WGmVBp0Ms9LaRsGVHuF5ljMcfGyHxEREcUqc7fIDDnpu10Jb4a24TilV+jB6NS89uP+3AZz96y/GaL2qiHmMcyHqfoPS2RZP/nJ/wdOq0pFwlWT9QAAAABJRU5ErkJggg==" alt="ACS Logo" style="height: 64px; display: block; margin: 0 auto 12px auto;">
  <h1 id="appHeading">Azure Communication Services<br/>Email Domain Checker</h1>
  <div class="input-row">
    <div class="input-wrapper">
      <input id="domainInput" type="text" placeholder="example.com" oninput="toggleClearBtn()" />
      <button id="clearBtn" class="clear-btn" type="button" onclick="clearInput()">&#x2715;</button>
    </div>
    <button id="lookupBtn" class="primary hide-on-screenshot" type="button" onclick="lookup()">Lookup</button>
  </div>
  <div id="history" class="history hide-on-screenshot"></div>
</div>
<div id="status" class="engage-section"></div>
<div id="azureDiagnosticsCard" class="card hide-on-screenshot engage-section" style="display:none; margin-bottom: 12px;">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="chevron">&#x25BC;</span>
    <span class="tag tag-info" id="azureDiagnosticsTag">AZURE</span>
    <strong id="azureDiagnosticsTitle">Azure Workspace Diagnostics</strong>
  </div>
  <div class="card-content">
    <div id="azureDiagnosticsHint" class="azure-note">Sign in to query customer Azure subscriptions and Log Analytics workspaces directly from your browser session.</div>
    <div id="azureSwitchDirectoryRow" class="azure-panel-field" style="display:none; margin-bottom:10px;">
      <label for="azureTenantInput" id="azureSwitchDirectoryLabel" style="font-size:12px;">Switch directory (tenant ID or domain)</label>
      <div style="display:flex; gap:6px;">
        <input id="azureTenantInput" type="text" placeholder="e.g. contoso.onmicrosoft.com" style="flex:1; padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--input-bg); color:var(--fg); font-size:13px;" />
        <button id="azureSwitchDirectoryBtn" type="button" onclick="switchAzureDirectory()" style="white-space:nowrap;">Switch</button>
      </div>
    </div>
    <div class="azure-panel-grid">
      <div class="azure-panel-field">
        <label for="azureSubscriptionSelect" id="azureSubscriptionLabel">Subscription</label>
        <select id="azureSubscriptionSelect"></select>
      </div>
      <div class="azure-panel-field">
        <label for="azureResourceSelect" id="azureResourceLabel">ACS Resource</label>
        <select id="azureResourceSelect"></select>
      </div>
      <div class="azure-panel-field">
        <label for="azureWorkspaceSelect" id="azureWorkspaceLabel">Workspace</label>
        <select id="azureWorkspaceSelect"></select>
      </div>
    </div>
    <div class="azure-panel-actions">
      <button id="azureRunInventoryBtn" type="button" class="primary" onclick="runAzureQueryTemplate('workspaceInventory')">Run workspace inventory</button>
      <button id="azureRunDomainSearchBtn" type="button" onclick="runAzureQueryTemplate('domainSearch')">Run domain search</button>
      <button id="azureRunAcsSearchBtn" type="button" onclick="runAzureQueryTemplate('acsSearch')">Run ACS search</button>
    </div>
    <div id="azureDiagnosticsStatus" class="azure-status"></div>
    <div id="azureDiagnosticsResults" class="azure-results-container"></div>
  </div>
</div>
<div id="results" class="cards"></div>

<div class="footer" id="footerText">
  ACS Email Domain Checker v__APP_VERSION__ &bull; Written by: <a href="https://blakedrumm.com/" style="color:inherit;">Blake Drumm</a> &bull; Generated by PowerShell &bull; <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Back to Top</a>
</div>

</div>

<script nonce="__CSP_NONCE__">
let lastResult = null;
const HISTORY_KEY = "acsDomainHistory";
const LANG_KEY = "acsLanguage";

'@
