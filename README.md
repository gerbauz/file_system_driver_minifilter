# file_system_driver_minifilter
Minifilter for managnin write and read operations in specified directory.
You can read "read_write_test_program" to check driver functionality.

#define CONFIG_PATH L"\\??\\C:\\dr_config.txt" - here place path of configuration file

#define TARGET_PATH "\\mbks5\\" - here place target directory

**Config format:** [PID] [FILE] [RIGHTS]

*Example:* 1337 test.txt rw
