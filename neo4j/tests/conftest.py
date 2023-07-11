from compose.config.config import ConfigFile
from py2neo import Graph
from requests.exceptions import ConnectionError
import pytest
import requests

from pathlib import Path
import random, string
import uuid

SERVICE_NAME = 'neo4j'
BOLT_PORT = 7687
REST_PORT = 7474


@pytest.fixture(scope='session')
def neo4j_env(docker_compose_file):
    path = Path(docker_compose_file).resolve()
    if not path.exists:
        raise FileNotFoundError
    conf = ConfigFile.from_filename(path)
    try:
        env = conf.config['services'][SERVICE_NAME]['environment']
        return dict(map(lambda x: x.split('='), env))
    except KeyError:
        return dict()


def is_responsive(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except ConnectionError:
        return False


@pytest.fixture(scope='session')
def neo4j_service(docker_ip, docker_services):
    """Ping the rest url until neo4j is up. Return the bolt url for transactions."""

    bolt_port = docker_services.port_for(SERVICE_NAME, BOLT_PORT)
    bolt_url = f'bolt://{docker_ip}:{bolt_port}'

    rest_port = docker_services.port_for(SERVICE_NAME, REST_PORT)
    rest_url = f'http://{docker_ip}:{rest_port}/'

    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_responsive(rest_url))

    return bolt_url


@pytest.fixture(scope='function')
def empty_graph(neo4j_service, neo4j_env):
    """Empty Graph for Testing."""
    name = ''.join(random.choices(string.ascii_letters, k=16))
    auth = neo4j_env['NEO4J_AUTH'].split('/')
    graph = Graph(neo4j_service, auth=tuple(auth))
    graph.run(f'CREATE DATABASE {name} WAIT')
    yield Graph(neo4j_service, auth=tuple(auth), name=name)

    graph.run(f'DROP DATABASE {name} WAIT')
