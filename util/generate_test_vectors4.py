"""
Generates test vectors for testing of CVSS library. All of them are created using cvsslib
from https://pypi.python.org/pypi/cvsslib .

Simple vectors are all vector combinations without any optional values.
Random vectors are 100,000 randomly generated vectors.
Runs only with Python 3 because cvsslib does not support Python 2.
"""
import time

from generate_constants import METRICS_4, NAMES_4, build_constants

from tqdm.contrib.itertools import product
import asyncio
from pyppeteer import launch

metrics_abbreviations, metrics_mandatory, metrics_values, metrics_value_names = build_constants(METRICS_4, NAMES_4, None)

metric_keys = list(metrics_abbreviations.keys())

def generate_vectors(available_keys=None):
    if not available_keys:
        available_keys = list(metrics_value_names.keys())

    lists = [
        list(metrics_value_names[key].keys()) for key in metrics_value_names.keys() if key in available_keys
    ]
    yield from product(*lists)

def print_vector(vector):
    str = 'CVSS:4.0/'
    for i, value in enumerate(vector):
        if value == "X":
            continue
        str += f'{metric_keys[i]}:{value}/'
    return str[:-1]  # Remote tailing slash

async def generate_scores(metrics, filename):
    print('Starting browser')
    browser = await launch(headless=False, args=['--no-sandbox', '--disable-setuid-sandbox'])

    print('Opening new page')
    page = await browser.newPage()

    print('Requesting calculator')
    await page.goto('https://www.first.org/cvss/calculator/cvsscalc40', waitUntil='domcontentloaded')
    time.sleep(1)

    print('Placing script')
    await page.addScriptTag(content='''
function timeout(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function calculate(vector) {
    window.location.hash = vector
    await timeout(10) // Time to update UI
    const score = document.querySelector('h5.score-line').textContent.substr(18)
    const macro = document.querySelector('blockquote sup.mb-2').textContent.substr(14)
    return [score, macro]
}''')

    # Open the detail view
    await page.evaluate('''document.querySelector('h5.score-line span').click()''')

    print('Calculating vectors')
    with open(filename, 'w+') as fout:
        for vector in generate_vectors(metrics):
            vector_str = print_vector(vector)
            fout.write(vector_str)
            score = await page.evaluate(f'''(vector)=>calculate(vector)''', vector_str)
            value = score[0].split(' / ')[0]
            fout.write(f' - ({value}, {score[1]})\n')


asyncio.get_event_loop().run_until_complete(generate_scores(metrics_mandatory, '../tests/vectors_simple4'))
