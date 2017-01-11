using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cipher_GOST
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox2.Text = Encryption.encode(textBox1.Text, "vladosvladosvladosvladosvladosvlados");
            
        }

        private void button2_Click(object sender, EventArgs e)
        {
            textBox3.Text = Encryption.decode(textBox1.Text, "vladosvladosvladosvladosvladosvlados");
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}
