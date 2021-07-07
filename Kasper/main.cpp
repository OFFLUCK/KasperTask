#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <unistd.h>


using namespace std;


// Checks if string has such substring.
bool Checker(string str, string key) {
    if (str.length() < key.length()) {
        return false;
    }
    for (int i = 0; i < str.length() - key.length(); i++) {
        if (str.substr(i, key.length()) == key) {
            return true;
        }
    }
    return false;
}


// Adds essential number of zeros to int.
string Formatting(string format, int num) {
    string s = to_string(num);
    for (int i = 0; i < format.length() - s.length(); i++) {
        s = "0" + s;
    }
    return s;
}


class VirusDetector {
public:
    int FileCounter;
    int JSVirus;
    int UnixVirus;
    int MacOSVirus;
    int Errors;
    string Path;
    time_t Timer;

    VirusDetector(string path) {
        Timer = time(0);
        // Needed it for testing.
        // sleep(10);
        FileCounter = 0;
        JSVirus = 0;
        UnixVirus = 0;
        MacOSVirus = 0;
        Errors = 0;
        Path = path;
    }

    // Gets all files from given directory.
    void GettingAllFiles() {
        string filePath;
        for (const auto &entry : filesystem::directory_iterator(Path)) {
            try {
                FileCounter++;
                filePath = entry.path();
                // Catching different viruses.
                if (filePath.substr(filePath.length() - 3, 3) == ".js") {
                    CheckJSFile(filePath);
                } else {
                    CheckUnixFile(filePath);
                    CheckMacOSFile(filePath);
                }
            }
                // If something wrong with the file.
            catch (...) {
                Errors++;
            }
        }
    }

    void Output() {
        cout << "====== Scan result ======" << endl;
        cout << "Processed files: " << FileCounter << endl;
        cout << "JS detects: " << JSVirus << endl;
        cout << "Unix detects: " << UnixVirus << endl;
        cout << "macOS detects: " << MacOSVirus << endl;
        cout << "Errors: " << Errors << endl;
        int t = time(0) - Timer;
        // Getting hours, minutes and seconds from timer.
        int hours = t / 3600;
        int minutes = (t % 3600) / 60;
        int seconds = t % 60;
        cout << "Exection time: " << Formatting("XX", hours) << ":" << Formatting("XX", minutes) << ":"
             << Formatting("XX", seconds) << endl;
        cout << "=========================" << endl;
    }


private:
    // Checks JS files.
    void CheckJSFile(string path) {
        string s;
        ifstream f(path);
        f.exceptions(std::ios::badbit);
        while (f >> s) {
            if (!Checker(s, "<script>evil_script()</script>")) {
                JSVirus++;
                return;
            }
        }
    }

    // Checks Unix-viruses in files.
    void CheckUnixFile(string path) {
        string s;
        ifstream f(path);
        f.exceptions(std::ios::badbit);
        while (f >> s) {
            if (!Checker(s, "rm -rf ~/Documents")) {
                UnixVirus++;
                return;
            }
        }
    }

    // Checks MacOS-viruses in file.
    void CheckMacOSFile(string path) {
        string s;
        ifstream f(path);
        f.exceptions(std::ios::badbit);
        while (f >> s) {
            if (!Checker(s, "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")")) {
                MacOSVirus++;
                return;
            }
        }
    }
};


int main(int argc, char **argv) {
    // Getting arguments from Terminal.
    if (argc == 2) {
        string s = argv[1];
        VirusDetector virusDetector(s);
        virusDetector.GettingAllFiles();
        virusDetector.Output();
    } else {
        cout << "Wrong Input" << endl;
    }
    return 0;
}