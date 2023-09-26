#include <string.h>

using namespace std;

class Advertisement_Manager {  
    private:
        float prices[5] = {9.99, 14.99, 7.99, 11.99, 6.99}; 
        string categories[5] = {"Books", "Clothing", "Food", "Tools", "Furniture"};
        string titles[5] = {"Principia Mathematica", "Green Pants", "Cheddar cheese", "Kitchen knife set", "Cotton curtains"};
    
    public:
        string generate_advertisement1() {
            int i = (rand()) % 5;
            string ad;
            ad.append(to_string(prices[i]) + "\n");
            ad.append(categories[i] + "\n");
            ad.append(titles[i] + "\n");
            return ad;
        }


};