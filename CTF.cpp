#include <iostream>
#include <string.h>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        return 1;
    }

    cout << "25%" << endl;
    if (argv[1][0] + argv[1][1] == 217) {
        cout << "50%" << endl;
        if (argv[1][2] == 104 && argv[1][3] == 110) {
            cout << "75%" << endl;
            if (argv[2][0] + argv[2][1] + argv[2][2] + argv[2][3] + argv[2][4] == 526) {
                cout << "You have successfully found the flag 100%" << endl;
            }
        }
    }

    return 0;
}
