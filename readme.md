# GDPR Checker

# Citing Our Paper

if you use our tool, please cite the following paper-

[CHKPLUG: Checking GDPR Compliance of WordPress Plugins via Cross-language Code Property Graph](https://www.ndss-symposium.org/ndss-paper/chkplug-checking-gdpr-compliance-of-wordpress-plugins-via-cross-language-code-property-graph/)


```
@inproceedings{shezan2023chkplug,
  title={CHKPLUG: Checking GDPR Compliance of WordPress Plugins via Cross-language Code Property Graph.},
  author={Shezan, Faysal Hossain and Su, Zihao and Kang, Mingqing and Phair, Nicholas and Thomas, Patrick William and van Dam, Michelangelo and Cao, Yinzhi and Tian, Yuan},
  booktitle={NDSS},
  year={2023}
}
```


## Usage

### `batch-run.sh`

An alternative to running `build-and-run-docker.sh` and `load-docker-results-to-neo4j.sh` is to just run `batch-run.sh`. The script itself requires some configuration, and it also requires `load-docker-results-to-neo4j.sh` to be configured (since it is used in the script). By default it runs `neo4j/src/Encryption.py` on all of the websites and plugins in `navex_docker/exampleApps` and `navex_docker/Plugins`, however this can be changed.

The script can take a single argument too, where the argument should be a relative path to some website or plugin, like `navex_docker/exampleApps/gdprplugin`. This runs the entire process (Docker, then Neo4j import, then Python script) on a plugin.

The script saves all output outside of the repository into `../output`.

Configuation should be done with environment variables. 
```bash
$ ./batch-run.sh -h
usage: ./batch-run.sh [-n <dbmsname>] [plugin]
  plugin: path to a single plugin to analyze (default: APP_PATHS constant)

  -n <dbmsname>: name prefix to identify NEO4J dbms when not explicitly set (default: Graph DBMS)

ENVIRONMENT
  NEO4J_HOME: Path to NEO4J DBMS
  NEO4J_USERNAME: Username for connecting to NEO4J DBMS
  NEO4J_PASSWORD: Password for connecting to NEO4J DBMS
  SUDO_PASSWORD: sudo Password for Linux


$ SUDO_PASSWORD="SUDO password" ./batch-run.sh /path/to/plugin
export NEO4J_PASSWORD=1

NEO4J_PASSWORD=1 SUDO_PASSWORD=30153015 ./batch-run.sh

```

Setting `NEO4J_HOME` is not strictly required. The tool will try to discover the location
of the NEO4J DBMS for you. By default it looks for a DBMS whose name begins 
with "Graph DBMS". You can specify an alternate name with the `-n` switch.
In the case where multiple DBMSs of the same name are found, the first discovered
is used.


### Alternative: Entirely Within Docker

In `/util` There is a script, `run-local.sh`, which runs the entire program (NAVEX, PHP Joern, JS Joern, Esprima, Python programs, etc.) within Docker. At the beginning of the script are three variables that need to be configured per installation:

- `PROJ_DIR` - The root directory of the repository.
- `PLUGINS` - Directory containing all of the plugins to be analyzed.
- `RESULTS` - Directory to dump results into.

There are also two options that can be supplied to the script:

- `-b` - Only build the Docker image and do not run the program.
- `-n <number of processes>` - Start `n` copies of the program to more efficiently use resources on a single machine.

### Alternative: Via Singularity

Similarly to the above section, the entire project can also be ran in Singularity. Running `rivanna/build.sh` builds the same Docker image as the previous section, however now it is also compressed into a Singularity image. All relevant directories should be configured to be mounted at the end of `rivanna/run.sh`. However, the configuration of some local variables (normally begin with `LOCAL_`) in the script may need to be configured.

## Interpreting Results

### SQLITE output

From the configured `RESULTS` folder, a file `results.sqlite` can be found. Use a SQLite reader to open it and browse data collected by the tool. The database contains the following tables:

- `Detectors` - The results collected by the detector modules.
- `PathAnalyzer` - The analyzed results of plugins, with analysis of whether GDPR laws are required for plugins and whether the plugins satisfy the laws.
- `PathAnalyzerDecision` - Overview of `PathAnalyzer`. Only contains the final compliance decisions.
- `Paths` - (Deprecated)
- `Plugins` - The list of plugins the tool has run on.
- `SourceSink` - Source sink pairs for sensitive data for each plugin analyzed. The recorded numbers are node IDs in Neo4J, so this result is only useful for analyzing plugins' graph in Neo4J.

### Text log

From the configured `RESULTS` folder, there is an `output` folder that contains the text logs for each run of the tool. The text logs contain detector results, and path analyzer results, as well as more detailed logs to keep track of all internal steps of a given run (e.g., the time taken for each step can be found).

