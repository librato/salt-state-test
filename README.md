# Depenencies

This is primarily used with python 2.7.10 and saltstack 2015.5.4, and
deepdiff version 0.5.4.

# Setting up tests for your state files.

The unit testing we have for salt states tests whether a salt 
state can render, and when it renders it confirms that the output
of the state being rendered matches the desired output.


## This directory 

### The config.json file

The config.json file currently only requires the key "states_dir" and
the value "states/" to tell the test script where to find its states
relative to the root of the git repo.  The "/" at the end of states is
important don't forget it.

### The global grains file

There is a grains.json file in this directory that will be used to 
simulate a system.

## The per-state test file and its contents

In each state directory, the directory "test" must exist.

### The pillar file

In the ```<statename>/test``` directory there will be a file called
pillar.json.  This will be read and used as the pillars for all of the
states that are tested.

### The output file

So, if you're testing a state called foo.init, then its filename will be
foo/init.sls.  When the test is run, it will apply the grains and the
pillar values that are provided to the foo.init state and compare the output
to a json document called foo/test/init.json and fail if there are differences.

To create an output file, the test script can be invoked with the ```-j``` flag as follows:

```
python test/test_salt_state.py -j  states/jolokia/init.sls
```

And in this case a rendered json document will be sent to stdout.  That
document should be used as the baseline for the tests by placing it into
```states/jolokia/tests/init.json``` (in this example).

