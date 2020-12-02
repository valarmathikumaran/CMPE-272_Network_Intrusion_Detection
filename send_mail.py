import smtplib
import datetime
import socket

def send_mail(x_attack):

    from_email = 'XXXX@gmail.com'
    to_email = 'XXXX@gmail.com'

    conn = smtplib.SMTP('imap.gmail.com',587)
    conn.ehlo()
    conn.starttls()
    conn.login(from_email, 'XXXXX')
    conn.sendmail(from_email , to_email , 'Subject: IDS ALERT FROM {host} \n\n {attack_type} DETECTED AT {timestamp}.'
                                          ' PLEASE, REVIEW THE DETAILS'.format(host=socket.gethostname() ,
                                                                           attack_type=x_attack ,
                                                                           timestamp=datetime.datetime.now()))

    conn.quit()