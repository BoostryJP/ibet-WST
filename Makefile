.PHONY: install setup update format lint compile test

install:
	uv sync --frozen --no-install-project
	uv run pre-commit install
	npm install

setup:
	brownie pm delete OpenZeppelin/openzeppelin-contracts@5.3.0
	brownie pm install OpenZeppelin/openzeppelin-contracts@5.3.0
	brownie networks import conf/networks.yml true

update:
	uv lock --upgrade
	npm update

format:
	uv run ruff format && uv run ruff check --fix --select I
	npx prettier --write --plugin=prettier-plugin-solidity contracts/**/*.sol

lint:
	uv run ruff check --fix

compile:
	brownie compile

test:
	uv run pytest --network=test_network tests/ ${ARG}
