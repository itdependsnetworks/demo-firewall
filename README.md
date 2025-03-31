Basic demo showing the ability to parse Check Point data and generate Palo Alto Configurations.



commands

```bash
git clone https://github.com/itdependsnetworks/demo-firewall
cd demo-firewall
poetry shell
poetry install
python cli.py parse-checkpoint
python cli.py publish
python cli.py generate-config
```