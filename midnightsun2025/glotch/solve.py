from PIL import Image
import numpy as np

def print_image(image_path):
    img = Image.open(image_path)
    img_array = np.array(img)

    space = img_array[-1][0].copy()

    for column in img_array[0:24]:
        print("")
        for pixel in column[0:500]:
            if pixel.any() == space.any():
                print("0", end="")
            else:
                print("1", end="")


def swap_image_rows(
    image_path, row1_index, row2_index, output_path="swapped_image.png"
):
    try:
        img = Image.open(image_path)
        img_array = np.array(img)

        num_rows = img_array.shape[0]

        if not (0 <= row1_index < num_rows and 0 <= row2_index < num_rows):
            print("指定された行インデックスは画像の範囲外です。")
            return

        # 行を入れ替える
        temp_row = img_array[row1_index].copy()
        img_array[row1_index] = img_array[row2_index]
        img_array[row2_index] = temp_row

        # NumPy配列をPIL Imageオブジェクトに戻す
        swapped_img = Image.fromarray(img_array)
        swapped_img.save(output_path)

    except FileNotFoundError:
        print(f"エラー: ファイル '{image_path}' が見つかりません。")
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")

def copy_image(src, dst):
    img = Image.open(src)
    img_array = np.array(img)
    swapped_img = Image.fromarray(img_array)
    swapped_img.save(dst)


# def copy_image_from_processed_image(image_path):
#     img = Image.open(PROCESSED_IMAGE)
#     img_array = np.array(img)
#     swapped_img = Image.fromarray(img_array)
#     swapped_img.save(image_path)


def swap_rows_blocked(
    image_path, row1_index, row2_index, output_path="swapped_image.png"
):
    copy_image(image_path, output_path)
    row1_base = row1_index * 3
    row2_base = row2_index * 3
    for i in range(3):
        swap_image_rows(output_path, row1_base + i, row2_base + i, output_path)


def decode(

    image_path, row1_index, row2_index, output_path="swapped_image.png"
):
    img = Image.open(image_path)
    img_array = np.array(img)
    for i in range(39):




if __name__ == "__main__":
    input_image_path = "flag1.png"  # 処理したい画像のパスに置き換えてください
    row_index1_to_swap = 0
    row_index2_to_swap = 1
    output_image_path = "swapped_output.png"

    # 367

    print_image(input_image_path)
    print("hello")
    swap_rows_blocked(
        input_image_path, row_index1_to_swap, row_index2_to_swap, output_image_path
    )
    print_image(output_image_path)
