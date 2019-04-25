#include <iostream>
#include <string>
#include <fstream>
#include <exception>


void read_file(std::string& filename)
{
	std::ifstream in;
	std::string line;

	in.open(filename);

	if (in.is_open())
	{
		while (std::getline(in, line))
		{
			std::cout << line << std::endl;
		}
		in.close();
	}
	else
		throw std::string("Error reading file.\n");
}

void write_file(std::string& filename)
{
	std::ofstream out;
	std::string user_input;

	out.open(filename);

	try
	{
		if (out.is_open())
		{
			std::cin >> user_input;
			out << user_input;
		}
		else
			throw std::string("Error writing to file.\n");
	}
	catch (std::exception exc)
	{
		std::cout << exc.what();
	}

}

int main()
{
	std::string filename;
	int menu;

	do
	{
		std::cout << "Enter filename: ";
		std::cin >> filename;
		std::cout << "1. Read file\n2. Write to file\n3. Exit" << std::endl;
		std::cin >> menu;
		try
		{
			switch (menu)
			{
			case 1:
			{
				read_file(filename);
				break;
			}
			case 2:
			{
				write_file(filename);
				break;
			}
			default:
				break;
			}
		}
		catch (std::string & err)
		{
			std::cout << err;
		}
	} while (menu != 3);

	return 0;
}